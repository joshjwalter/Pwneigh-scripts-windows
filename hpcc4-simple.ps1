# HPCC4 defensive helper: backup, firewall, unauthorized-account removal, local passwords, tools, ACL lock.
# HPCC4-SIMPLE-SCRIPT v1 - stable identity marker; keep this exact line if you rename or copy this file (reset-hpcc4.ps1 and the pre-edit hook key off it, not the filename).
# Ordinary independent failures are recorded; cancellation stops ordinary work. Windows PowerShell 5.1 x64; Server enforcement needs VM verification.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', 'Write-Log', Justification = 'Defined in this script')]
param([switch]$DryRun, [switch]$Unlock, [switch]$Cleanup)
# ---- Tunables (edit operator configuration here) ----
$KeepOpenTcp    = @(22)        # open for the WHOLE run, along with the live RDP port (22 = SSH, just in case)
$AllowTcp       = @(3389)      # scored-service TCP ports; opened at the END of the run
$AllowUdp       = @()          # scored-service UDP ports, e.g. 53 for DNS; opened at the END of the run
$BlockTcp       = @()          # inbound TCP to block, e.g. 21, 23
$BlockUdp       = @()          # inbound UDP to block
$ExcludeUsers   = @()          # never change these passwords (and never delete these accounts)
$AuthorizedUsers = @()         # local accounts from the packet. Every OTHER non-built-in local account is DELETED ('@()' = skip deleting)
$ToolsDir       = 'C:\Tools'
$ToolsZip       = ''           # local path OR https URL to your tools .zip (files at the zip's root)
$ToolsZipSha256 = ''           # if set, reject a zip whose SHA256 doesn't match
$AvInstallerUrl = 'https://free.360totalsecurity.com/totalsecurity/360TS_Setup_Mini.exe'   # protected role staging; opens at the END for you to click through ('' = skip)
$AvInstallerExpectedSigner = '' # if set, substring match against the installer's Authenticode signer subject; empty = only validity is checked (current behavior)
$InstallSysmon  = $false       # true = install/update Sysmon if Sysmon64.exe and sysmonconfig.xml are in the zip
$BackupPaths    = @('C:\Windows\System32\drivers\etc\hosts')
$LockPaths      = @('C:\Windows\System32\drivers\etc\hosts')
$OutDir         = 'C:\HPCC4'   # protected content/firewall backups and full persistence report; journal uses OS bootstrap
# ---- Extra services (the STIG GPO owns the standard service baseline - use this only for extras the packet names) ----
$DisableServices = @()         # extra services to stop + disable, e.g. 'RemoteRegistry', 'TlntSvr', 'SNMP'
# ---- DoD STIG GPO (needs LGPO.exe) ----
$DodGpoDir = ''                # folder holding extracted STIG GPO backups (each a subfolder with a Backup.xml). '' = skip
$DodGpoSelection = @()         # explicit ordered manifest; see gpo-selection-contract.md
$LgpoExe   = ''                # explicit LGPO.exe input; '' = use LGPO from this run's accepted archive
$script:SourcePath = $PSCommandPath
# Common runtime. Definitions alone acquire no identity, storage or native approval.
function New-RunState {
    $script:State = @{
        RunId = [guid]::NewGuid().ToString('D'); StartedAtUtc = [datetime]::UtcNow.ToString('o')
        Mode = $(if ($Unlock) { 'Unlock' } elseif ($DryRun) { 'DryRun' } else { 'Normal' })
        Preconditions = @{ RecoveryEligible = $false; NativeApprovals = @{}; RecoveryPlan = @{ RuleOperations = @(); ProfileOperations = @(); StartupDecisionEstablished = $false } }
        Operations = @(); Failures = @(); Cancelled = $false; RecoveryStatus = 'NotEligible'
        IsDC = $null; RdpPort = 0; BackupDir = ''; Uncovered = @(); Purge = $false; Enable = $false; FirewallOn = $false
        RulesAdded = @(); BlocksRefused = @(); Deleted = @(); Changed = @(); ServicesDisabled = @(); Persistence = @()
        GpoApplied = @(); ToolsInstalled = $false; HashChecked = 'no'; AvInstaller = ''; Locked = @()
    }
    $script:State
}
function Test-RunCancellation {
    param($ErrorObject)
    $exception = if ($ErrorObject -is [Management.Automation.ErrorRecord]) { $ErrorObject.Exception } else { $ErrorObject }
    for ($i = 0; $null -ne $exception -and $i -lt 16; $i++) {
        if ($exception -is [Management.Automation.PipelineStoppedException] -or $exception -is [OperationCanceledException]) { return $true }
        $exception = $exception.InnerException
    }
    return $false
}
function Add-RunFailure {
    param([string]$Stage, [string]$Operation, [string]$Detail)
    # Callers supply fixed reason codes/type names, never secret arguments/error text.
    $clean = @(@($Stage, $Operation, $Detail) | ForEach-Object { $text=([string]$_ -replace '[\x00-\x1f\x7f]', ' '); $text.Substring(0, [Math]::Min(256, $text.Length)) })
    $script:State.Failures += [pscustomobject]@{ Stage = $clean[0]; Operation = $clean[1]; Detail = $clean[2] }
}
function Invoke-Step {
    param([Parameter(Mandatory, Position=0)][string]$Name, [Parameter(Mandatory, Position=1)][scriptblock]$Action)
    $operation = [pscustomobject]@{ Stage = 'Step'; Name = $Name; Status = 'Planned'; Reason = ''; Requested = $true; Observed = $null }
    $script:State.Operations += $operation
    if ($DryRun) { Write-RunLog "WOULD: $Name"; return $false }
    try {
        $local:ErrorActionPreference = 'Stop'
        $output = @(& $Action 2>&1)
        if (@($output | Where-Object { $_ -is [Management.Automation.ErrorRecord] }).Count) { throw 'Managed operation emitted an error' }
        $operation.Status = 'Succeeded'; $operation.Observed = $true
        Write-RunLog "DONE: $Name"
        return $true
    } catch {
        if (Test-RunCancellation $_) { $script:State.Cancelled = $true; $operation.Status = 'Unknown'; throw }
        $operation.Status = 'Failed'; $operation.Reason = $_.Exception.GetType().Name
        Add-RunFailure 'Step' $Name $operation.Reason
        Write-RunLog "FAILED: $Name ($($operation.Reason))"
        return $false
    }
}
function Write-RunLog {
    param([string]$Message)
    try { $null=Write-Log $Message }
    catch {
        if (Test-RunCancellation $_) { $script:State.Cancelled=$true; throw }
        Add-RunFailure 'Reporting' 'Log' $_.Exception.GetType().Name
    }
}
function Invoke-Stage {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Action)
    try {
        $local:ErrorActionPreference = 'Stop'
        $output = @(& $Action 2>&1)
        if (@($output | Where-Object { $_ -is [Management.Automation.ErrorRecord] }).Count) { throw 'Stage emitted an error' }
    } catch {
        if (Test-RunCancellation $_) { $script:State.Cancelled = $true; throw }
        Add-RunFailure $Name 'Prepare' $_.Exception.GetType().Name
    }
}
function Get-CurrentWindowsIdentity { [Security.Principal.WindowsIdentity]::GetCurrent() }
function Test-IsAdmin {
    $identity = Get-CurrentWindowsIdentity
    try { (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    finally { if ($null -ne $identity) { $identity.Dispose() } }
}
function Get-CanonicalFilePath {
    param([Parameter(Mandatory)][string]$Path, [switch]$MustExist)
    if ($Path -notmatch '^[a-zA-Z]:[\\/]' -or $Path -match '[\x00-\x1f*?~]' -or $Path.Substring(2).Contains(':')) { throw 'Unsupported local path' }
    foreach($part in $Path.Substring(3).Replace('/','\').Split('\')){if(($part.EndsWith('.') -and $part -notin '.','..') -or $part.EndsWith(' ')){throw 'Unsupported original path component'}}
    Assert-LocalVolume ($Path.Substring(0,2))
    $full = [IO.Path]::GetFullPath($Path.Replace('/', '\')).TrimEnd('\')
    if ($full.Length -le 2) { throw 'Volume roots are unsupported targets' }
    foreach ($part in $full.Substring(3).Split('\')) {
        if (-not $part -or $part.EndsWith('.') -or $part.EndsWith(' ') -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') { throw 'Unsupported path component' }
    }
    if ($MustExist) {
        $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
        if ($item.PSProvider.Name -ne 'FileSystem') { throw 'Filesystem required' }
        if ($item.FullName.TrimEnd('\') -ine $full) { throw 'Unsupported path alias' }
    }
    $full
}
function Test-PathWithin {
    param([string]$Candidate, [string]$Parent)
    $c = Get-CanonicalFilePath $Candidate; $p = Get-CanonicalFilePath $Parent
    [bool]($c.Equals($p, [StringComparison]::OrdinalIgnoreCase) -or $c.StartsWith($p + '\', [StringComparison]::OrdinalIgnoreCase))
}
function Get-OsSystemDirectory { [Environment]::SystemDirectory }
function Get-RuntimeEngineInfo { [pscustomobject]@{Edition=$PSVersionTable.PSEdition;Version=$PSVersionTable.PSVersion;Is64Bit=[Environment]::Is64BitProcess;Platform=[Environment]::OSVersion.Platform.ToString()} }
function Assert-SupportedEngine {
    $engine=Get-RuntimeEngineInfo
    $supported=($engine.Edition -eq 'Desktop' -and $engine.Version.Major -eq 5 -and $engine.Version.Minor -eq 1) -or ($engine.Edition -eq 'Core' -and $engine.Version -ge [version]'7.5')
    if (-not $engine.Is64Bit -or $engine.Platform -ne 'Win32NT' -or -not $supported) { throw 'Windows x64 PowerShell Desktop 5.1 or Core 7.5 or later required' }
}
function Get-TextDigest {
    param([string]$Text)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { -join ($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) } finally { $hash.Dispose() }
}
function Get-NativeFileDigest { param([string]$Path); (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
function Get-TrustedNativePath {
    param([Parameter(Mandatory)][string]$Name)
    Assert-SupportedEngine
    $paths = @{ 'icacls.exe'='icacls.exe'; 'attrib.exe'='attrib.exe'; 'robocopy.exe'='robocopy.exe'; 'netsh.exe'='netsh.exe'; 'gpupdate.exe'='gpupdate.exe'; 'appcmd.exe'='inetsrv\appcmd.exe'; 'powershell.exe'='WindowsPowerShell\v1.0\powershell.exe' }
    if (-not $paths.ContainsKey($Name)) { throw 'Unapproved inbox native name' }
    $path = Get-CanonicalFilePath (Join-Path (Get-OsSystemDirectory) $paths[$Name]) -MustExist
    Assert-TrustedPath $path
    $identity = (Get-RecoveryObject $path).Identity
    $script:State.Preconditions.NativeApprovals[$path] = @{ Role=$Name; Digest=(Get-NativeFileDigest $path); TrustPolicy='Inbox'; ResourceIdentity=$identity }
    $path
}
function Register-NativeApproval {
    param([string]$ExecutablePath, [ValidateSet('LGPO','Sysmon','AV')][string]$Role, [string]$Digest, [ValidateSet('PinnedDigest','ValidSignature','ExpectedSigner')][string]$TrustPolicy, [hashtable]$ResourceIdentity)
    $path = Get-CanonicalFilePath $ExecutablePath -MustExist
    Assert-TrustedPath $path
    $current = (Get-RecoveryObject $path).Identity
    if (-not (Test-DataEqual $current $ResourceIdentity) -or $Digest -notmatch '^[a-fA-F0-9]{64}$' -or (Get-NativeFileDigest $path) -ine $Digest) { throw 'External approval identity/digest mismatch' }
    if ($TrustPolicy -ne 'PinnedDigest') {
        $signature = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        if ($signature.Status -ne 'Valid') { throw 'External signature not valid' }
        if ($TrustPolicy -eq 'ExpectedSigner' -and (-not $AvInstallerExpectedSigner -or $signature.SignerCertificate.Subject -notlike ('*' + [WildcardPattern]::Escape($AvInstallerExpectedSigner) + '*'))) { throw 'External signer mismatch' }
    }
    $script:State.Preconditions.NativeApprovals[$path] = @{ Role=$Role; Digest=$Digest.ToLowerInvariant(); TrustPolicy=$TrustPolicy; ResourceIdentity=$current }
}
function Assert-NativeApproval {
    param([string]$ExecutablePath)
    $path = Get-CanonicalFilePath $ExecutablePath -MustExist
    $approval = $script:State.Preconditions.NativeApprovals[$path]
    if (-not $approval) { throw 'External executable blocked: no protected role approval' }
    Assert-TrustedPath $path
    if (-not (Test-DataEqual (Get-RecoveryObject $path).Identity $approval.ResourceIdentity) -or (Get-NativeFileDigest $path) -ine $approval.Digest) { throw 'Approved executable changed' }
    if ($approval.TrustPolicy -eq 'Inbox') {
        $expected = Get-TrustedNativePath $approval.Role
        if ($expected -ine $path) { throw 'Inbox role mismatch' }
    } elseif ($approval.TrustPolicy -in 'ValidSignature','ExpectedSigner') {
        $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        if ($sig.Status -ne 'Valid') { throw 'External signature changed' }
        if ($approval.TrustPolicy -eq 'ExpectedSigner' -and (-not $AvInstallerExpectedSigner -or $sig.SignerCertificate.Subject -notlike ('*' + [WildcardPattern]::Escape($AvInstallerExpectedSigner) + '*'))) { throw 'External signer changed' }
    } elseif ($approval.TrustPolicy -ne 'PinnedDigest') { throw 'Unknown native trust policy' }
}
function Invoke-NativeLeaf {
    param([string]$ExecutablePath, [string[]]$Arguments)
    & $ExecutablePath @Arguments 2>&1
}
function New-NativeFailure {
    param($ExitCode,[string]$Classification,[object[]]$Output)
    $diagnostics=[object[]]@(for($index=0;$index -lt $Output.Count;$index++) {
        $item=$Output[$index]
        [pscustomobject]@{Index=$index;Kind=$(if($item -is [Management.Automation.ErrorRecord]){'ErrorRecord'}else{'Output'});Type=$(if($null -eq $item){'Null'}else{$item.GetType().FullName});Category=$(if($item -is [Management.Automation.ErrorRecord]){$item.CategoryInfo.Category.ToString()}else{'NotApplicable'})}
    })
    $detail=[pscustomobject]@{ExitCode=$ExitCode;Classification=$Classification;DiagnosticCount=$Output.Count;Diagnostics=$diagnostics}
    [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('Native invocation failed (arguments and diagnostic text withheld)'),'Hpcc4NativeInvocationFailed',[Management.Automation.ErrorCategory]::InvalidResult,$detail)
}
function Invoke-NativeCommand {
    param([Parameter(Mandatory)][string]$ExecutablePath, [string[]]$Arguments = @(), [int[]]$SuccessExitCodes = @(0))
    Assert-NativeApproval $ExecutablePath
    if (-not $SuccessExitCodes.Count) { throw 'Native success codes required' }
    # Legacy Windows command-line marshalling cannot preserve these uniformly.
    foreach ($argument in $Arguments) { if ($null -eq $argument -or $argument.Length -eq 0 -or $argument.Contains('"') -or $argument.Contains([char]0) -or ($argument -match '\s' -and $argument.EndsWith('\'))) { throw 'Unsupported native argument: empty, quote, NUL or ambiguous trailing separator' } }
    $variable = Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    $existed = $null -ne $variable
    $prior = if ($existed) { $variable.Value } else { $null }
    if ($existed -and ($variable.Options -band ([Management.Automation.ScopedItemOptions]::ReadOnly -bor [Management.Automation.ScopedItemOptions]::Constant))) { throw 'Global native exit state is protected' }
    $local:ErrorActionPreference = 'Continue'
    $local:PSNativeCommandUseErrorActionPreference = $false
    $local:PSNativeCommandArgumentPassing = 'Standard'
    $result = $null
    $output=@(); $exitCode=$null; $classification='LaunchFailure'; $primary=$null
    try {
        Set-Variable LASTEXITCODE -Scope Global -Value 0 -ErrorAction Stop
        $output = @(Invoke-NativeLeaf $ExecutablePath $Arguments 2>&1)
        $exitCode = (Get-Variable LASTEXITCODE -Scope Global -ErrorAction Stop).Value
        if ($exitCode -isnot [int]) { throw 'Native exit status missing' }
        foreach ($item in $output) {
            if ($item -is [Management.Automation.ErrorRecord]) {
                if (Test-RunCancellation $item) { throw $item }
                if ($item.FullyQualifiedErrorId -notin 'NativeCommandError','NativeCommandErrorMessage' -or $item.Exception -isnot [Management.Automation.RemoteException]) { $classification='PowerShellError'; throw 'Native launch or PowerShell error' }
            }
        }
        if ($exitCode -notin $SuccessExitCodes) { $classification='UnacceptableExit'; throw 'Native exit not accepted' }
        $result = [pscustomobject]@{ ExitCode=[int]$exitCode; Output=[object[]]$output }
    } catch {
        if (Test-RunCancellation $_) { $script:State.Cancelled=$true; $primary=$_ }
        else { $primary=New-NativeFailure $exitCode $classification $output }
        throw $primary
    } finally {
        try {
            if ($existed) { Set-Variable LASTEXITCODE -Scope Global -Value $prior -ErrorAction Stop }
            else { Remove-Variable LASTEXITCODE -Scope Global -ErrorAction Stop }
        } catch {
            Add-RunFailure 'Native' 'RestoreGlobalExit' $_.Exception.GetType().Name
            if ($primary -and (Test-RunCancellation $primary)) { throw $primary }
            if (Test-RunCancellation $_) {
                $script:State.Cancelled=$true
                if ($primary) { Add-RunFailure 'Native' 'Invocation' $primary.Exception.GetType().Name }
                throw
            }
            if ($primary) { throw $primary }
            throw (New-NativeFailure $exitCode 'GlobalRestoreFailure' $output)
        }
    }
    $result
}
function Start-ApprovedInstaller {
    param([string]$ExecutablePath)
    if ($DryRun) { return $false }
    Assert-NativeApproval $ExecutablePath
    $path = Get-CanonicalFilePath $ExecutablePath -MustExist
    if ($script:State.Preconditions.NativeApprovals[$path].Role -ne 'AV') { throw 'Interactive AV role required' }
    $null=Start-InstallerLeaf $path
    return $true
}
function Start-InstallerLeaf { param([string]$Path); $null = Start-Process -FilePath $Path -ErrorAction Stop }

# Protected recovery metadata uses one deterministic bootstrap and one held lock.
function Initialize-ObjectIdentityApi {
    if ('Hpcc4ObjectIdentity' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class Hpcc4ObjectIdentity {
 [StructLayout(LayoutKind.Sequential)] public struct SecurityAttributes { public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle; }
 [DllImport("kernel32.dll", EntryPoint="CreateDirectoryW", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)] public static extern bool CreateDirectory(string path, ref SecurityAttributes security);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern uint QueryDosDevice(string name, System.Text.StringBuilder target, int length);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool GetVolumeNameForVolumeMountPoint(string root, System.Text.StringBuilder name, int length);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool GetVolumePathNamesForVolumeName(string name, [Out] char[] paths, uint length, out uint required);
 [StructLayout(LayoutKind.Sequential)] public struct Info { public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write; public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
 public static void CreateProtectedDirectory(string path, byte[] descriptor) {
  var pinned=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
  try {
   var security=new SecurityAttributes { Length=Marshal.SizeOf(typeof(SecurityAttributes)), Descriptor=pinned.AddrOfPinnedObject(), InheritHandle=false };
   if(!CreateDirectory(path,ref security)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  } finally { pinned.Free(); }
 }
 public static string Read(string path) {
  using(var handle=CreateFile(path,0,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero)) {
   if(handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   Info info; if(!GetFileInformationByHandle(handle,out info)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   if((info.Attributes & 1024)!=0) throw new InvalidOperationException("Reparse object refused");
   return info.Volume.ToString("x8")+":"+info.IndexHigh.ToString("x8")+info.IndexLow.ToString("x8");
  }
 }
}
'@ -ErrorAction Stop
}
function Get-LocalVolume {
    param([string]$Drive)
    Initialize-ObjectIdentityApi
    $target=New-Object Text.StringBuilder 4096
    if ([Hpcc4ObjectIdentity]::QueryDosDevice($Drive,$target,$target.Capacity) -eq 0) { throw 'Local volume mapping unavailable' }
    $info=New-Object IO.DriveInfo($Drive+'\')
    $volumeName=New-Object Text.StringBuilder 1024
    if(-not [Hpcc4ObjectIdentity]::GetVolumeNameForVolumeMountPoint($Drive+'\',$volumeName,$volumeName.Capacity)){throw 'Volume mount identity unavailable'}
    $buffer=New-Object char[] 32768; $required=[uint32]0
    if(-not [Hpcc4ObjectIdentity]::GetVolumePathNamesForVolumeName($volumeName.ToString(),$buffer,$buffer.Length,[ref]$required)){throw 'Volume aliases unavailable'}
    $roots=@((-join $buffer).Split([char]0) | Where-Object {$_})
    [pscustomobject]@{ Mapping=$target.ToString(); Format=$info.DriveFormat; Type=$info.DriveType.ToString(); Roots=[object[]]$roots }
}
function Assert-LocalVolume {
    param([string]$Drive)
    $volume=Get-LocalVolume $Drive
    # Refuse SUBST/network/device aliases and ReFS's unsupported 64-bit file IDs.
    if ($volume.Mapping -notmatch '^\\Device\\HarddiskVolume\d+$' -or $volume.Format -ne 'NTFS' -or $volume.Type -ne 'Fixed' -or @($volume.Roots).Count -ne 1 -or $volume.Roots[0] -ine ($Drive+'\')) { throw 'Unsupported local volume or alias' }
}
function Get-RecoveryObject {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSProvider.Name -ne 'FileSystem' -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsupported recovery object' }
    Initialize-ObjectIdentityApi
    $identity = [Hpcc4ObjectIdentity]::Read($item.FullName)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if ([Hpcc4ObjectIdentity]::Read($item.FullName) -ne $identity) { throw 'Object changed during inspection' }
    [pscustomobject]@{ Path=$item.FullName; Directory=[bool]$item.PSIsContainer; Attributes=[int]$item.Attributes; Acl=$acl; Identity=@{ Policy='VolumeFileId'; Value=$identity }; Length=$(if ($item.PSIsContainer) { 0 } else { $item.Length }) }
}
function Assert-ObjectProtection {
    param($Object, [switch]$NoChildCreate, [switch]$Confidential, [switch]$CheckChildInheritance)
    if (-not $Object -or -not $Object.Acl -or ($Object.Attributes -band 1024) -or -not $Object.Identity) { throw 'Unreadable or reparse security descriptor' }
    $privileged = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $raw = New-Object Security.AccessControl.RawSecurityDescriptor($Object.Acl.Sddl)
    if ($null -eq $raw.DiscretionaryAcl -or $raw.Owner.Value -notin $privileged) { throw 'Untrusted owner or null DACL' }
    $danger = 0x50000000 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40 -bor 0x10 -bor 0x100
    if ($NoChildCreate -or -not $Object.Directory) { $danger = $danger -bor 0x2 -bor 0x4 }
    $admin = $false; $system = $false
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback) { throw 'Unsupported DACL ACE' }
        if ([int]$ace.AceFlags -band [int][Security.AccessControl.AceFlags]::InheritOnly) {
            if(-not $CheckChildInheritance -or -not ([int]$ace.AceFlags -band [int][Security.AccessControl.AceFlags]::ContainerInherit)){continue}
        }
        if ($ace.AceQualifier -eq 'AccessDenied') {
            if ($Confidential) { throw 'Unsupported deny in protected metadata DACL' }
            continue
        }
        if ($ace.AceQualifier -ne 'AccessAllowed') { throw 'Unsupported access rule' }
        if ($ace.SecurityIdentifier.Value -notin $privileged -and (($ace.AccessMask -band $danger) -ne 0 -or $Confidential)) { throw 'Untrusted mutation or metadata access' }
        if ($Confidential -and $ace.SecurityIdentifier.Value -notin 'S-1-5-18','S-1-5-32-544') { throw 'Metadata principal not allowed' }
        if (($ace.AccessMask -band 0x1f01ff) -eq 0x1f01ff) {
            if ($ace.SecurityIdentifier.Value -eq 'S-1-5-18') { $system = $true }
            if ($ace.SecurityIdentifier.Value -eq 'S-1-5-32-544') { $admin = $true }
        }
    }
    if ($Confidential -and (($Object.Directory -and -not $Object.Acl.AreAccessRulesProtected) -or -not $admin -or -not $system)) { throw 'Metadata DACL not protected and usable' }
}
function Assert-TrustedPath {
    param([string]$Path, [switch]$NoChildCreate, [switch]$Confidential, [switch]$CheckChildInheritance)
    $full = if ($Path -match '^[a-zA-Z]:\\$') { $Path } else { Get-CanonicalFilePath $Path -MustExist }
    $chain = @(); $cursor = $full
    while ($cursor) { $chain = @($cursor) + $chain; $cursor = [IO.Path]::GetDirectoryName($cursor) }
    foreach ($part in $chain) {
        $object = Get-RecoveryObject $part
        if ($part -ne $full -and -not $object.Directory) { throw 'Non-directory path ancestor' }
        Assert-ObjectProtection $object -NoChildCreate:($NoChildCreate -and $part -eq $full) -Confidential:($Confidential -and $part -eq $full) -CheckChildInheritance:($CheckChildInheritance -and $part -eq $full)
    }
}
function New-RecoverySecurity {
    param([switch]$File)
    $acl=if($File){New-Object Security.AccessControl.FileSecurity}else{New-Object Security.AccessControl.DirectorySecurity}
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in 'S-1-5-18','S-1-5-32-544') {
        $rule=if($File){New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'Allow')}else{New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')}
        $acl.AddAccessRule($rule)
    }
    return $acl
}
function Assert-RecoveryCreateApi {
    if($PSVersionTable.PSEdition -eq 'Desktop') {
        $file=@([IO.FileStream].GetConstructors() | Where-Object {($_.GetParameters().ParameterType.FullName -join '|') -eq 'System.String|System.IO.FileMode|System.Security.AccessControl.FileSystemRights|System.IO.FileShare|System.Int32|System.IO.FileOptions|System.Security.AccessControl.FileSecurity'})
    } else {
        $type='System.IO.FileSystemAclExtensions' -as [type]
        if(-not $type){throw 'Protected creation API unavailable'}
        $file=@($type.GetMethods() | Where-Object {$_.Name -eq 'Create' -and ($_.GetParameters().ParameterType.FullName -join '|') -eq 'System.IO.FileInfo|System.IO.FileMode|System.Security.AccessControl.FileSystemRights|System.IO.FileShare|System.Int32|System.IO.FileOptions|System.Security.AccessControl.FileSecurity'})
    }
    if($file.Count -ne 1){throw 'Protected creation API unavailable'}
}
function Set-RecoveryProtection {
    param([string]$Path)
    Set-Acl -LiteralPath $Path -AclObject (New-RecoverySecurity) -ErrorAction Stop
}
function New-RecoveryDirectory {
    param([string]$Path)
    $security=New-RecoverySecurity
    Initialize-ObjectIdentityApi
    # Win32 returns success only for a new creation; existing-name collisions
    # cannot be silently adopted or claimed as Created.
    try {[Hpcc4ObjectIdentity]::CreateProtectedDirectory($Path,$security.GetSecurityDescriptorBinaryForm())}
    catch {if(Test-RunCancellation $_){$script:State.Cancelled=$true;throw};throw 'Protected directory creation refused (collision or access failure)'}
}
function Initialize-ProtectedDirectory {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) { Assert-TrustedPath $Path -NoChildCreate -Confidential; return }
    Assert-TrustedPath ([IO.Path]::GetDirectoryName($Path)) -NoChildCreate -CheckChildInheritance
    New-RecoveryDirectory $Path
    Assert-TrustedPath $Path -NoChildCreate
    if (@(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop).Count) { throw 'New recovery directory is not empty' }
    Set-RecoveryProtection $Path
    Assert-TrustedPath $Path -NoChildCreate -Confidential
}
function Get-RecoveryMachineId {
    $value = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    $guid = [guid]::Empty
    if (-not [guid]::TryParse([string]$value, [ref]$guid) -or $guid -eq [guid]::Empty) { throw 'Machine identity unavailable' }
    $guid.ToString('D')
}
function Open-RecoveryLock {
    param([string]$Path, [switch]$ExistingOnly)
    if($ExistingOnly -or (Test-Path -LiteralPath $Path)){return [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
    Open-ProtectedRecoveryFile $Path
}
function Close-RecoverySession {
    if ($null -ne $script:RecoveryContext) {
        try { if ($null -ne $script:RecoveryContext.Handle) { $null=$script:RecoveryContext.Handle.Dispose() } }
        catch {
            Add-RunFailure 'Recovery' 'ReleaseLock' $_.Exception.GetType().Name
            $script:State.RecoveryStatus='Partial'
            if (Test-RunCancellation $_) { $script:State.Cancelled=$true; throw }
        }
        finally { $script:RecoveryContext = $null }
    }
}
function Open-RecoverySession {
    param([string]$OutDir, [switch]$ExistingOnly)
    Assert-SupportedEngine
    if ($null -ne $script:RecoveryContext) { throw 'Recovery session already open' }
    Assert-RecoveryCreateApi
    $canonical = Get-CanonicalFilePath $OutDir
    # Refuse alias/reparse paths even when the final target has not been created.
    $ancestor = $canonical
    while (-not (Test-Path -LiteralPath $ancestor)) { $ancestor = [IO.Path]::GetDirectoryName($ancestor); if (-not $ancestor) { throw 'No existing target ancestor' } }
    Assert-TrustedPath $ancestor
    $machine = Get-RecoveryMachineId
    $parent = Join-Path (Get-OsSystemDirectory) 'config'
    Assert-TrustedPath $parent -NoChildCreate
    $base = Join-Path $parent 'HPCC4-Recovery'
    $root = Join-Path $base (Get-TextDigest ($machine + '|' + $canonical.ToUpperInvariant()))
    if ($DryRun) { return [pscustomobject]@{ Status='NotScanned'; Root=$root } }
    if ($ExistingOnly) {
        if (-not (Test-Path -LiteralPath $root)) { return [pscustomobject]@{ Status='Absent'; Root=$root } }
        Assert-TrustedPath $base -NoChildCreate -Confidential
        Assert-TrustedPath $root -NoChildCreate -Confidential
    } else { Initialize-ProtectedDirectory $base; Initialize-ProtectedDirectory $root }
    $lock = Join-Path $root 'writer.lock'
    if (Test-Path -LiteralPath $lock) { Assert-TrustedPath $lock -Confidential }
    $handle = Open-RecoveryLock $lock -ExistingOnly:$ExistingOnly
    $script:RecoveryContext = @{ Root=$root; OutDir=$canonical; MachineId=$machine; Handle=$handle; Promoted=$false }
    try {
        $lockedObject=Get-RecoveryLockObject $lock $handle
        Assert-ObjectProtection $lockedObject -Confidential
        # Lock descriptor inherits the verified parent. It is inspected through
        # the held handle's path only after acquisition; no second lock opener.
        $read = Read-RecoveryRecords $canonical
        if ($read.Status -notin 'Complete','Absent') { throw 'Recovery metadata requires manual inspection' }
        [pscustomobject]@{ Status='Complete'; Root=$root }
    } catch {
        $primary=$_
        if(Test-RunCancellation $primary){$script:State.Cancelled=$true}else{Add-RunFailure 'Recovery' 'OpenSession' $primary.Exception.GetType().Name}
        Close-RecoverySession
        throw $primary
    }
}
function Get-RecoveryLockObject {
    param([string]$Path, $Handle)
    # FileShare.None prevents a second identity opener. The retained handle
    # establishes the object; ACL inspection is by its nonreplaceable path.
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    [pscustomobject]@{ Directory=$false; Attributes=0; Identity=@{ Policy='HeldExclusiveHandle' }; Acl=$acl }
}
function New-ReadResult {
    param([ValidateSet('Complete','Absent','Partial','Failed','NotScanned')][string]$Status, [object[]]$Items=@(), [object[]]$Errors=@())
    [pscustomobject]@{ Status=$Status; Items=[object[]]$Items; Errors=[object[]]$Errors; ObservedAtUtc=[datetime]::UtcNow.ToString('o') }
}
function ConvertTo-RecoveryData {
    param($Value, [int]$Depth=0, [switch]$FromJson)
    if($FromJson -and $Value -is [decimal]){return [double]$Value}
    if ($Depth -gt 16) { throw 'Metadata depth exceeded' }
    if ($Value -is [long] -and $Value -ge [int]::MinValue -and $Value -le [int]::MaxValue) { return [int]$Value }
    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [int] -or $Value -is [long]) { return $Value }
    if ($Value -is [string]) {if($Value.Length -gt 32768){throw 'Metadata string bound exceeded'};return $Value}
    if ($Value -is [double]) {if([double]::IsNaN($Value) -or [double]::IsInfinity($Value)){throw 'Nonfinite metadata number'};return $Value}
    if ($Value -is [Collections.IDictionary]) {
        if($Value.Count -gt 128){throw 'Metadata map bound exceeded'}
        $map=@{}; foreach ($key in $Value.Keys) {if($key -isnot [string] -or $key.Length -gt 512 -or $map.ContainsKey($key)){throw 'Unsupported metadata key'};$map[$key]=ConvertTo-RecoveryData $Value[$key] ($Depth+1) -FromJson:$FromJson }; return $map
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $map=@{}; foreach ($property in $Value.PSObject.Properties) { $map[$property.Name]=ConvertTo-RecoveryData $property.Value ($Depth+1) -FromJson:$FromJson }; return $map
    }
    if ($Value -is [array]) { if($Value.Count -gt 1024){throw 'Metadata array bound exceeded'};$array=@(foreach ($item in $Value) { ConvertTo-RecoveryData $item ($Depth+1) -FromJson:$FromJson }); return ,$array }
    throw 'Unsupported metadata value'
}
function Get-StableDataText {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [Collections.IDictionary]) {
        $pairs=@(foreach ($key in @($Value.Keys | Sort-Object)) { (ConvertTo-Json -InputObject ([string]$key) -Compress)+':'+(Get-StableDataText $Value[$key]) })
        return ('{'+($pairs -join ',')+'}')
    }
    if ($Value -is [array]) {
        $parts=@(foreach ($item in $Value) { Get-StableDataText $item })
        return ('['+($parts -join ',')+']')
    }
    ConvertTo-Json -InputObject $Value -Compress -Depth 20
}
function Test-DataEqual { param($Left,$Right); (Get-StableDataText $Left) -ceq (Get-StableDataText $Right) }
function Assert-RecoveryRecord {
    param([hashtable]$Record)
    $fields='SchemaVersion','RecordId','Revision','RunId','MachineId','Kind','ResourceId','ResourceIdentity','CanonicalPath','Ownership','State','Prior','IntendedState','AppliedObservation','Artifact','ChangedByRun','Limits'
    if ($Record.Count -ne $fields.Count) { throw 'Recovery schema fields mismatch' }
    foreach ($field in $fields) { if (-not $Record.ContainsKey($field)) { throw 'Missing recovery field' } }
    if ($Record.SchemaVersion -isnot [int] -or $Record.SchemaVersion -ne 1 -or $Record.Revision -isnot [int] -or $Record.Revision -lt 1 -or $Record.Revision -gt 1000000) { throw 'Recovery version/revision invalid' }
    foreach ($field in 'RecordId','RunId','MachineId') { $guid=[guid]::Empty; if ($Record[$field] -isnot [string] -or -not [guid]::TryParse($Record[$field],[ref]$guid) -or $guid -eq [guid]::Empty -or $Record[$field] -cne $guid.ToString('D')) { throw 'Recovery GUID must be a canonical nonempty D string' } }
    if ($Record.Kind -isnot [string] -or $Record.Ownership -isnot [string] -or $Record.State -isnot [string] -or $Record.Kind -notin 'Storage','Acl','Firewall','Registry','Service','Tool','Artifact','LocalPolicy' -or $Record.Ownership -notin 'Created','Preexisting' -or $Record.State -notin 'Intent','Applied','RestoreFailed','Restored') { throw 'Unknown recovery kind/state' }
    if ($Record.ChangedByRun -isnot [bool] -or $Record.ResourceId -isnot [string] -or -not $Record.ResourceId -or $Record.ResourceId.Length -gt 512 -or $Record.CanonicalPath -isnot [string] -or $Record.Limits -isnot [array]) { throw 'Recovery data invalid' }
    if ((Get-CanonicalFilePath $Record.CanonicalPath) -cne $Record.CanonicalPath) { throw 'Noncanonical recovery path' }
    if ($null -ne $Record.ResourceIdentity -and ($Record.ResourceIdentity -isnot [hashtable] -or -not $Record.ResourceIdentity.Count)) { throw 'Invalid resource identity' }
    if ($Record.State -eq 'Intent' -and $null -ne $Record.AppliedObservation) { throw 'Intent cannot claim observed application' }
    if ($Record.State -eq 'Applied' -and ($null -eq $Record.AppliedObservation -or $null -eq $Record.ResourceIdentity)) { throw 'Applied record requires checked identity/observation' }
    if ($Record.Artifact -isnot [hashtable] -or $Record.Artifact.Count -ne 3 -or -not $Record.Artifact.ContainsKey('CanonicalPath') -or -not $Record.Artifact.ContainsKey('Digest') -or $Record.Artifact.Complete -isnot [bool]) { throw 'Invalid artifact schema' }
    if($Record.Artifact.CanonicalPath -isnot [string] -or $Record.Artifact.Digest -isnot [string]){throw 'Artifact data must be strings'}
    if($Record.Artifact.CanonicalPath -and (Get-CanonicalFilePath $Record.Artifact.CanonicalPath) -cne $Record.Artifact.CanonicalPath){throw 'Noncanonical artifact path'}
    if($Record.Artifact.Digest -and $Record.Artifact.Digest -notmatch '^[a-fA-F0-9]{64}$'){throw 'Invalid artifact digest'}
    if ($Record.Artifact.Complete) {
        $artifact = Get-CanonicalFilePath $Record.Artifact.CanonicalPath -MustExist
        if ($Record.Artifact.Digest -notmatch '^[0-9a-fA-F]{64}$') { throw 'Missing artifact digest' }
        Assert-TrustedPath $artifact -Confidential
        if ((Get-NativeFileDigest $artifact) -ine $Record.Artifact.Digest) { throw 'Artifact digest mismatch' }
    }
    if ($script:RecoveryContext -and $Record.MachineId -ne $script:RecoveryContext.MachineId) { throw 'Recovery machine mismatch' }
    $null = ConvertTo-RecoveryData $Record
}
function Read-RecoveryRecords {
    param([string]$OutDir, [string]$Kind='')
    $items=@(); $errors=@()
    try {
        if (-not $script:RecoveryContext -or (Get-CanonicalFilePath $OutDir) -ine $script:RecoveryContext.OutDir -or -not $script:RecoveryContext.Handle) { throw 'Held recovery session required' }
        if ($Kind -and $Kind -notin 'Storage','Acl','Firewall','Registry','Service','Tool','Artifact','LocalPolicy') { throw 'Unknown requested record kind' }
        Assert-TrustedPath $script:RecoveryContext.Root -NoChildCreate -Confidential
        $files=@(Get-ChildItem -LiteralPath $script:RecoveryContext.Root -Force -ErrorAction Stop)
        if ($files.Count -gt 1025) { throw 'Recovery file count exceeded' }
        $ids=@{}; $resources=@{}
        foreach ($file in $files) {
            if ($file.Name -eq 'writer.lock' -and -not $file.PSIsContainer) { continue }
            try {
                if ($file.PSIsContainer -or $file.Name -notmatch '^[0-9a-fA-F-]{36}\.json$' -or $file.Length -gt 1048576 -or $file.Length -le 0) { throw 'Unknown, interrupted or oversized metadata' }
                Assert-TrustedPath $file.FullName -Confidential
                $json=Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
                $decoded=if($PSVersionTable.PSEdition -eq 'Core'){ConvertFrom-Json -InputObject $json -DateKind String -ErrorAction Stop}else{ConvertFrom-Json -InputObject $json -ErrorAction Stop}
                $record=ConvertTo-RecoveryData $decoded -FromJson
                Assert-RecoveryRecord $record
                if ($file.BaseName -ine $record.RecordId -or $ids.ContainsKey($record.RecordId)) { throw 'Duplicate or mismatched record identity' }
                $ids[$record.RecordId]=$true
                $key=$record.Kind+'|'+$record.ResourceId
                if ($record.State -ne 'Restored' -and $resources.ContainsKey($key)) { throw 'Duplicate active resource' }
                if ($record.State -ne 'Restored') { $resources[$key]=$true }
                $items += $record
            } catch { if(Test-RunCancellation $_){$script:State.Cancelled=$true;throw};$errors += 'InvalidOrInterruptedRecoveryMetadata' }
        }
        if ($errors.Count) { return New-ReadResult $(if ($items.Count) { 'Partial' } else { 'Failed' }) $items $errors }
        $selected=@($items | Where-Object { -not $Kind -or $_.Kind -eq $Kind })
        New-ReadResult $(if ($selected.Count) { 'Complete' } else { 'Absent' }) $selected
    } catch { if(Test-RunCancellation $_){$script:State.Cancelled=$true;throw};New-ReadResult 'Failed' @() @('RecoveryReadRefused') }
}
function Open-ProtectedRecoveryFile {
    param([string]$Path)
    $security=New-RecoverySecurity -File
    if($PSVersionTable.PSEdition -eq 'Desktop'){return [IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::ReadWrite,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$security)}
    [IO.FileSystemAclExtensions]::Create((New-Object IO.FileInfo($Path)),[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::ReadWrite,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$security)
}
function Open-RecoveryWrite { param([string]$Path); Open-ProtectedRecoveryFile $Path }
function Set-RecoveryBytes { param($Stream,[byte[]]$Bytes); $Stream.Write($Bytes,0,$Bytes.Length) }
function Flush-RecoveryWrite { param($Stream); $Stream.Flush($true) }
function Close-RecoveryWrite { param($Stream); $Stream.Dispose() }
function Write-RecoveryBytes {
    param([string]$Path, [byte[]]$Bytes)
    $stream=Open-RecoveryWrite $Path
    $primary=$null
    try { Set-RecoveryBytes $stream $Bytes; Flush-RecoveryWrite $stream }
    catch {
        $primary=$_
        if (Test-RunCancellation $primary) { $script:State.Cancelled=$true }
        throw
    } finally {
        try { Close-RecoveryWrite $stream }
        catch {
            Add-RunFailure 'Recovery' 'CloseRecord' $_.Exception.GetType().Name
            if ($primary -and (Test-RunCancellation $primary)) { throw $primary }
            if (Test-RunCancellation $_) {
                $script:State.Cancelled=$true
                if ($primary) { Add-RunFailure 'Recovery' 'WriteRecord' $primary.Exception.GetType().Name }
                throw
            }
            if ($primary) { throw $primary }
            throw
        }
    }
}
function Publish-RecoveryFile {
    param([string]$Temporary, [string]$Committed)
    if ([IO.File]::Exists($Committed)) { [IO.File]::Replace($Temporary,$Committed,[System.Management.Automation.Language.NullString]::Value) }
    else { [IO.File]::Move($Temporary,$Committed) }
}
function Write-RecoveryRecord {
    param([Parameter(Mandatory)][hashtable]$Record)
    if ($DryRun) { return }
    if (-not $script:RecoveryContext -or -not $script:RecoveryContext.Handle) { throw 'Held recovery session required' }
    Assert-RecoveryRecord $Record
    $read=Read-RecoveryRecords $script:RecoveryContext.OutDir
    if ($read.Status -notin 'Complete','Absent') { throw 'Recovery metadata not healthy' }
    $old=@($read.Items | Where-Object { $_.RecordId -eq $Record.RecordId })
    $active=@($read.Items | Where-Object { $_.Kind -eq $Record.Kind -and $_.ResourceId -eq $Record.ResourceId -and $_.State -ne 'Restored' -and $_.RecordId -ne $Record.RecordId })
    if ($active.Count) { throw 'Duplicate active original refused' }
    if ($old.Count) {
        if ($old[0].State -eq 'Restored' -or $Record.Revision -ne ($old[0].Revision+1) -or -not (Test-DataEqual $old[0].Prior $Record.Prior) -or $old[0].Kind -ne $Record.Kind -or $old[0].ResourceId -ne $Record.ResourceId -or $old[0].CanonicalPath -ine $Record.CanonicalPath -or $old[0].Ownership -ne $Record.Ownership) { throw 'Stale revision or original replacement refused' }
        if($null -ne $old[0].ResourceIdentity -and -not(Test-DataEqual $old[0].ResourceIdentity $Record.ResourceIdentity)){throw 'Active resource identity replacement refused'}
        if ($Record.State -eq 'Intent') { throw 'Cannot regress an existing record to Intent' }
    } elseif ($Record.Revision -ne 1 -or $Record.State -ne 'Intent') { throw 'New records must start at Intent revision 1' }
    $json=ConvertTo-Json -InputObject $Record -Depth 20 -Compress
    $bytes=[Text.Encoding]::UTF8.GetBytes($json)
    if ($bytes.Length -gt 1048576) { throw 'Recovery metadata too large' }
    $committed=Join-Path $script:RecoveryContext.Root ($Record.RecordId+'.json')
    $temporary=Join-Path $script:RecoveryContext.Root ($Record.RecordId+'.'+[guid]::NewGuid().ToString('N')+'.pending')
    Write-RecoveryBytes $temporary $bytes
    Assert-TrustedPath $temporary -Confidential
    Publish-RecoveryFile $temporary $committed
}
function Get-IntentRecoveryDisposition {
    param([hashtable]$Record, [hashtable]$ObservedIdentity, $CurrentState)
    Assert-RecoveryRecord $Record
    if ($Record.State -ne 'Intent' -or -not $Record.ResourceIdentity -or -not (Test-DataEqual $Record.ResourceIdentity $ObservedIdentity)) { return 'Unknown' }
    if (Test-DataEqual $Record.Prior $CurrentState) { return 'NoChange' }
    if ($null -ne $Record.IntendedState -and (Test-DataEqual $Record.IntendedState $CurrentState)) { return 'ExactIntendedState' }
    'Unknown'
}
function Initialize-RecoveryStorage {
    $session=Open-RecoverySession $OutDir -ExistingOnly:$Unlock
    if ($DryRun) { return $true }
    if ($Unlock) { return ($session.Status -eq 'Complete') }
    $read=Read-RecoveryRecords $OutDir 'Storage'
    if ($read.Status -notin 'Complete','Absent') { throw 'Storage metadata unreadable' }
    $active=@($read.Items | Where-Object { $_.State -ne 'Restored' })
    if ($active.Count -eq 1 -and $active[0].State -eq 'Intent' -and $active[0].Ownership -eq 'Preexisting') {
        Assert-TrustedPath $OutDir -NoChildCreate -Confidential
        $object=Get-RecoveryObject $OutDir
        $current=@{ Exists=$true; Sddl=$object.Acl.Sddl; Attributes=$object.Attributes; Identity=$object.Identity }
        if ((Get-IntentRecoveryDisposition $active[0] $object.Identity $current) -eq 'NoChange') {
            $retired=$active[0]; $retired.Revision++; $retired.State='Restored'; $retired.AppliedObservation=$current
            Write-RecoveryRecord $retired
            $active=@()
        }
    }
    if ($active.Count) {
        if ($active.Count -ne 1 -or $active[0].State -ne 'Applied') { throw 'Interrupted storage setup requires checked recovery' }
        Assert-TrustedPath $OutDir -NoChildCreate -Confidential
        $object=Get-RecoveryObject $OutDir
        if (-not (Test-DataEqual $object.Identity $active[0].ResourceIdentity) -or -not (Test-DataEqual @{ Identity=$object.Identity; Sddl=$object.Acl.Sddl; Attributes=$object.Attributes } $active[0].AppliedObservation)) { throw 'Storage identity or protection conflict' }
        $script:RecoveryContext.Promoted=$true
        return $true
    }
    $exists=Test-Path -LiteralPath $OutDir
    $identity=$null; $prior=@{ Exists=$false }
    if ($exists) {
        Assert-TrustedPath $OutDir -NoChildCreate -Confidential
        $object=Get-RecoveryObject $OutDir
        if (-not $object.Directory) { throw 'OutDir must be a directory' }
        $identity=$object.Identity
        $prior=@{ Exists=$true; Sddl=$object.Acl.Sddl; Attributes=$object.Attributes; Identity=$identity }
    }
    $record=@{ SchemaVersion=1; RecordId=[guid]::NewGuid().ToString('D'); Revision=1; RunId=$script:State.RunId; MachineId=$script:RecoveryContext.MachineId; Kind='Storage'; ResourceId=$script:RecoveryContext.OutDir.ToUpperInvariant(); ResourceIdentity=$identity; CanonicalPath=$script:RecoveryContext.OutDir; Ownership=$(if ($exists) { 'Preexisting' } else { 'Created' }); State='Intent'; Prior=$prior; IntendedState=$null; AppliedObservation=$null; Artifact=@{ CanonicalPath=''; Digest=''; Complete=$false }; ChangedByRun=$false; Limits=@('No automatic restore of an unobserved created identity') }
    Write-RecoveryRecord $record
    if (-not $exists) {
        Assert-TrustedPath ([IO.Path]::GetDirectoryName($OutDir))
        New-RecoveryDirectory $OutDir
        Assert-TrustedPath $OutDir -NoChildCreate
        if (@(Get-ChildItem -LiteralPath $OutDir -Force -ErrorAction Stop).Count) { throw 'New OutDir not empty' }
        Set-RecoveryProtection $OutDir
    }
    Assert-TrustedPath $OutDir -NoChildCreate -Confidential
    $observed=Get-RecoveryObject $OutDir
    $record.State='Applied'; $record.Revision=2; $record.ResourceIdentity=$observed.Identity
    $record.AppliedObservation=@{ Identity=$observed.Identity; Sddl=$observed.Acl.Sddl; Attributes=$observed.Attributes }; $record.ChangedByRun=(-not $exists)
    Write-RecoveryRecord $record
    Confirm-RecoveryPromotion
    return $true
}
function Confirm-RecoveryPromotion {
    # Keep bootstrap authoritative; promotion grants use of protected OutDir,
    # never copies active originals or moves/releases the bootstrap lock.
    Assert-TrustedPath $script:RecoveryContext.OutDir -NoChildCreate -Confidential
    $read=Read-RecoveryRecords $script:RecoveryContext.OutDir 'Storage'
    if ($read.Status -ne 'Complete' -or @($read.Items | Where-Object { $_.State -eq 'Applied' }).Count -ne 1) { throw 'Storage promotion unverified' }
    $script:RecoveryContext.Promoted=$true
}
function Get-RuntimeRole { (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).DomainRole }
function Get-RuntimeRdpPort { (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction Stop).PortNumber }
function Initialize-RunPreflight {
    Assert-SupportedEngine
    if (-not (Test-IsAdmin)) { throw 'Elevation required' }
    if ($Unlock -and $Cleanup) { throw 'Unlock and Cleanup cannot be combined' }
    $script:OutDir=Get-CanonicalFilePath $OutDir
    if ($Unlock) { return }
    $script:ToolsDir=Get-CanonicalFilePath $ToolsDir
    foreach ($path in @($BackupPaths)+@($LockPaths)) { $null=Get-CanonicalFilePath $path; if (Test-PathWithin $OutDir $path) { throw 'Backup/lock target contains recovery storage' } }
    if (Test-PathWithin $ToolsDir $OutDir) { throw 'Tools directory overlaps recovery storage' }
    if (Test-PathWithin $OutDir $ToolsDir) { throw 'Recovery directory overlaps tools' }
    if ($ToolsZipSha256 -and $ToolsZipSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'Invalid tools digest' }
    foreach ($port in @($KeepOpenTcp)+@($AllowTcp)+@($AllowUdp)+@($BlockTcp)+@($BlockUdp)) {
        if ([string]$port -notmatch '^\d+$' -or [long]$port -lt 1 -or [long]$port -gt 65535) { throw 'Invalid configured port' }
    }
    foreach($name in 'icacls.exe','attrib.exe','robocopy.exe','netsh.exe','gpupdate.exe'){$null=Get-TrustedNativePath $name}
    $role=Get-RuntimeRole
    if ($null -eq $role -or [string]$role -notmatch '^[0-5]$') { throw 'Unknown machine role' }
    $rdp=Get-RuntimeRdpPort
    if ([string]$rdp -notmatch '^\d+$' -or [long]$rdp -lt 1 -or [long]$rdp -gt 65535) { throw 'Invalid live RDP port' }
    $script:State.IsDC=([int]$role -in 4,5); $script:State.RdpPort=[int]$rdp
    $listeners=Get-ListeningPorts; $firewall=Get-FirewallSnapshot
    if($listeners.Status -ne 'Complete' -or $firewall.Status -ne 'Complete'){throw 'Required safety observation incomplete'}
    if(-not $State.IsDC){$accounts=Get-AccountSnapshot;if($accounts.Status -ne 'Complete'){throw 'Required account dependency observation incomplete'}}
    foreach($name in 'KeepOpenTcp','AllowTcp','AllowUdp','BlockTcp','BlockUdp'){Set-Variable -Name $name -Scope Script -Value @((Get-Variable $name -ValueOnly) | ForEach-Object {[int]$_} | Select-Object -Unique)}
    $operations=@()
    foreach ($port in @(Get-KeepPorts)) { $operations += @{ Label='Keep'; Proto='TCP'; Port=[int]$port } }
    foreach ($port in @($AllowTcp | Select-Object -Unique)) { if (@(Get-KeepPorts) -notcontains [int]$port) { $operations += @{ Label='Allow'; Proto='TCP'; Port=[int]$port } } }
    foreach ($port in @($AllowUdp | Select-Object -Unique)) { $operations += @{ Label='Allow'; Proto='UDP'; Port=[int]$port } }
    foreach($proto in 'TCP','UDP'){
        $blocks=if($proto -eq 'TCP'){$BlockTcp}else{$BlockUdp};$allows=if($proto -eq 'TCP'){@($AllowTcp)+@(Get-KeepPorts)}else{@($AllowUdp)}
        foreach($port in $blocks){if($allows -contains $port){$State.BlocksRefused+="${proto}:$port";Write-RunLog "REFUSED conflicting block ${proto}:$port"}else{$operations+=@{Label='Block';Proto=$proto;Port=[int]$port}}}
    }
    $script:State.Preconditions.RecoveryPlan.RuleOperations=$operations
    $script:State.Preconditions.RecoveryEligible=$true
}
function Invoke-FiniteRecovery {
    if ($Unlock -or -not $script:State.Preconditions.RecoveryEligible) { return }
    # An eligible attempt remains incomplete until every finite operation returns.
    $script:State.RecoveryStatus='Partial'
    $before=$script:State.Failures.Count
    try {
        foreach ($operation in $script:State.Preconditions.RecoveryPlan.RuleOperations) {
            Invoke-Stage 'RecoveryRule' { $null=Add-Rule $operation.Label $operation.Proto $operation.Port }
        }
        # D supplies actual startup authority. Empty/default State never enables profiles.
        if ($script:State.Preconditions.RecoveryPlan.StartupDecisionEstablished) {
            foreach ($operation in $script:State.Preconditions.RecoveryPlan.ProfileOperations) {
                if ($operation.Profile -notin 'Domain','Private','Public' -or $operation.Enabled -ne $true) { Add-RunFailure 'RecoveryProfile' 'Validate' 'InvalidFrozenOperation'; continue }
                $null=Invoke-Step 'recover authorized profile' {
                    foreach($port in @(Get-KeepPorts)){Assert-EffectiveControl "HPCC4-Keep-TCP-$port" 'TCP' $port}
                    Set-NetFirewallProfile -Profile $operation.Profile -Enabled True -ErrorAction Stop
                    $observed=Get-FirewallSnapshot
                    if($observed.Status -ne 'Complete' -or @($observed.Items[0].Profiles | Where-Object { $_.Name -eq $operation.Profile -and [string]$_.Enabled -eq 'True' }).Count -ne 1){throw 'Recovered profile not observed'}
                }
            }
        }
        $script:State.RecoveryStatus=if($DryRun){'Planned'}elseif ($script:State.Failures.Count -eq $before) { 'Complete' } else { 'Partial' }
    } catch {
        if (Test-RunCancellation $_) {
            $script:State.Cancelled=$true
            Add-RunFailure 'Recovery' 'Interrupted' $_.Exception.GetType().Name
        }
        throw
    }
}
function Get-TlsProtocol { [Net.ServicePointManager]::SecurityProtocol }
function Set-TlsProtocol { param($Value); [Net.ServicePointManager]::SecurityProtocol=$Value }
function Main {
    $null=New-RunState
    $bodyFinished=$false
    try {
    try {
        Initialize-RunPreflight
        Initialize-DeploymentIdentity $script:SourcePath
        if (-not (Initialize-Setup)) { throw 'Required storage setup failed' }
        if ($Unlock) {
            Invoke-Stage 'Unlock' { $null=Unlock-Paths }
        } else {
            Invoke-Stage 'Backup' { $null=Backup-Targets }
            Invoke-Stage 'Firewall' { $null=Set-FirewallLockdown }
            Invoke-Stage 'Accounts' { $null=Remove-UnauthorizedUsers }
            Invoke-Stage 'Passwords' { $null=Set-LocalPasswords }
            Invoke-Stage 'Services' { $null=Disable-ExtraServices }
            Invoke-Stage 'Persistence' { $null=Get-PersistenceReport }
            Invoke-Stage 'Tools' { $null=Install-Tools }
            Invoke-Stage 'GPO' { $null=Install-DodGpo }
            Invoke-Stage 'Locks' { $null=Lock-Paths }
        }
        $bodyFinished=$true
    } catch {
        if (Test-RunCancellation $_) { $script:State.Cancelled=$true }
        else { Add-RunFailure 'Main' 'Run' $_.Exception.GetType().Name }
    } finally {
        try { Invoke-Stage 'Recovery' { Invoke-FiniteRecovery } }
        finally {
            try {
                if ($bodyFinished -and -not $Unlock -and -not $script:State.Cancelled) {
                    if ($script:State.AvInstaller) { $null=Invoke-Step 'launch approved AV installer (acknowledgement only)' { $null=Start-ApprovedInstaller $script:State.AvInstaller } }
                    if ($Cleanup) { Invoke-Stage 'Cleanup' { $null=Invoke-Cleanup } }
                }
                if(-not $script:State.Cancelled){Invoke-Stage 'Summary' { Write-Summary }}
            }
            finally { Close-RecoverySession }
        }
    }
    } catch {
        if(Test-RunCancellation $_){$script:State.Cancelled=$true}
        else{Add-RunFailure 'Main' 'Finalize' $_.Exception.GetType().Name}
    }
    $status=if ($script:State.Cancelled) { 'Cancelled' } elseif ($script:State.Failures.Count) { 'Failed' } elseif ($DryRun) { 'DryRun' } else { 'Succeeded' }
    [pscustomobject]@{ Status=$status; Failures=[object[]]$script:State.Failures; RecoveryStatus=$script:State.RecoveryStatus; State=$script:State }
}
function Invoke-DirectEntry {
    $result=Main
    $result
    if ($result.Status -in 'Succeeded','DryRun') { exit 0 }
    exit 1
}

$null = New-RunState
$script:RecoveryContext = $null
# ---- Helpers ----
function Write-Log { param([string]$Message); Write-Host "$(Get-Date -Format 'HH:mm:ss') $Message" }   # terminal only; nothing is written to disk

# Restricts a folder to Administrators + SYSTEM full control (plus any extra grant), removing inherited permissions.
# Shared by Initialize-Setup ($OutDir) and Install-Tools ($ToolsDir) so the lockdown ACL is defined in exactly one place.
function Lock-AdminOnlyAcl {
    param([string]$Path, [string[]]$ExtraGrants=@())
    # B journals/protects OutDir through its bootstrap. This consumer does not
    # rewrite reused descriptors or assume inheritance removal removes grants.
    if ($ExtraGrants.Count) { throw 'Extra grant protection requires recorded storage integration; refused' }
    $canonical=Get-CanonicalFilePath $Path -MustExist
    if (-not $script:RecoveryContext -or -not $script:RecoveryContext.Handle -or -not $script:RecoveryContext.Promoted -or $canonical -ine $script:RecoveryContext.OutDir) { throw 'Verified promoted recovery storage required' }
    Assert-TrustedPath $canonical -NoChildCreate -Confidential
}

# ---- Firewall ----
function Get-ListeningPorts {
    try {
        $items=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {[pscustomobject]@{Proto='TCP';Port=[int]$_.LocalPort;Process=[int]$_.OwningProcess}})
        $items+=@(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {[pscustomobject]@{Proto='UDP';Port=[int]$_.LocalPort;Process=[int]$_.OwningProcess}})
        New-ReadResult 'Complete' @($items | Sort-Object Proto,Port -Unique)
    } catch {if(Test-RunCancellation $_){throw};New-ReadResult 'Failed' @() @('ListenerObservationFailed')}
}
# Ports that already have an enabled inbound allow rule, e.g. 'TCP:80'. Only single port numbers count (not ranges or Any): it may over-warn, never under-warn.
function Get-InboundAllowPorts {
    $read=Get-FirewallSnapshot
    if($read.Status -ne 'Complete'){return New-ReadResult 'Failed' @() @('FirewallObservationFailed')}
    $items=@(foreach($rule in $read.Items[0].Rules){if($rule.Enabled -eq 'True' -and $rule.Direction -eq 'Inbound' -and $rule.Action -eq 'Allow'){foreach($port in @($rule.Port.LocalPort)){if([string]$port -match '^\d+$'){[string]$rule.Port.Protocol+':'+[string]$port}}}})
    New-ReadResult 'Complete' $items
}
# Ports open for the whole run: the live RDP port plus $KeepOpenTcp. Their rules are named HPCC4-Keep-TCP-<port>.
function Get-KeepPorts { @(@($script:State.RdpPort) + @($KeepOpenTcp) | ForEach-Object { [int]$_ } | Select-Object -Unique) }
# Adds inbound rule HPCC4-<Label>-<Proto>-<Port>. Label 'Block' blocks; 'Keep' and 'Allow' allow.
function Add-Rule {
    param([string]$Label,[string]$Proto,[int]$Port)
    $name="HPCC4-$Label-$Proto-$Port";$action=if($Label -eq 'Block'){'Block'}else{'Allow'}
    $ok=Invoke-Step $name {
        $existing=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Name -eq $name)
        if ($existing.Count -gt 1) { throw 'Duplicate control identity' }
        if (-not $existing.Count) { $null=New-NetFirewallRule -Name $name -DisplayName $name -Direction Inbound -Protocol $Proto -LocalPort $Port -Action $action -Profile Any -PolicyStore PersistentStore -ErrorAction Stop }
        Assert-EffectiveControl $name $Proto $Port $action
    }
    if ($ok) { $State.RulesAdded += $name }
    return [bool]$ok
}
# Authorized local inbound purge requires -All. Keep controls and genuine DHCP client exceptions stay.
function Remove-InboundRules {
    param([switch]$All)
    if($State.IsDC -and $All){throw 'DC purge prohibited'}
    if($All -and (-not (Test-FirewallBackupReady) -or -not $State.Preconditions.RecoveryPlan.StartupDecisionEstablished)){throw 'Purge prerequisites missing'}
    $read=Get-FirewallSnapshot;if($read.Status -ne 'Complete'){throw 'Rule observation failed'}
    foreach($rule in $read.Items[0].Rules){
        if($rule.Source -ne 'Local' -or $rule.Direction -ne 'Inbound'){continue}
        if(-not $All -or $rule.Name -like 'HPCC4-Keep-*'){continue}
        $genuineDhcp=(Test-ControlRule $rule 'UDP' 68 'Allow' 67 'Dhcp') -or (Test-ControlRule $rule 'UDP' 546 'Allow' 547 'Dhcp')
        if($genuineDhcp){continue}
        $null=Invoke-Step "remove local inbound rule $($rule.Name)" {Remove-NetFirewallRule -InputObject $rule.Rule -ErrorAction Stop}
    }
}
function Enable-Firewall {
    param([switch]$BlockInbound)
    if(-not $State.Preconditions.RecoveryPlan.StartupDecisionEstablished){throw 'No startup profile authority'}
    foreach($port in @(Get-KeepPorts)){Assert-EffectiveControl "HPCC4-Keep-TCP-$port" 'TCP' $port}
    $read=Get-FirewallSnapshot;if($read.Status -ne 'Complete'){throw 'Profile observation failed'}
    foreach($profile in $read.Items[0].Profiles){
        $null=Invoke-Step "enable $($profile.Name) firewall" {
            if($BlockInbound -and -not $State.IsDC){Set-NetFirewallProfile -Profile $profile.Name -Enabled True -DefaultInboundAction Block -ErrorAction Stop}
            else{Set-NetFirewallProfile -Profile $profile.Name -Enabled True -ErrorAction Stop}
        }
    }
    $after=Get-FirewallSnapshot
    $State.FirewallOn=($after.Status -eq 'Complete' -and @($after.Items[0].Profiles | Where-Object {[string]$_.Enabled -ne 'True'}).Count -eq 0)
    if(-not $DryRun -and -not $State.FirewallOn){Add-RunFailure 'Firewall' 'ObserveProfiles' 'ProfilesNotObservedEnabled'}
}

# ---- Steps, in run order ----
function Initialize-Setup { Initialize-RecoveryStorage }
function Backup-Targets {
    if($DryRun){Write-Log 'WOULD: capture immutable content originals and a checked firewall export';return}
    Lock-AdminOnlyAcl $OutDir
    $read=Read-RecoveryRecords $OutDir 'Firewall'
    if($read.Status -notin 'Complete','Absent'){throw 'Firewall metadata unreadable'}
    $active=@($read.Items | Where-Object State -ne 'Restored')
    if($active.Count){
        if($active.Count -ne 1 -or $active[0].State -ne 'Applied'){throw 'Incomplete firewall original; manual recovery required'}
        Assert-BoundedRecoveryArtifact $active[0].Artifact 16777216
    }else{
        $path=Join-Path $OutDir ('firewall-'+[guid]::NewGuid().ToString('N')+'.wfw')
        Write-RecoveryBytes $path ([byte[]]@())
        $null=Invoke-NativeCommand (Get-TrustedNativePath 'netsh.exe') @('advfirewall','export',$path)
        $artifact=@{CanonicalPath=$path;Digest=Get-NativeFileDigest $path;Complete=$true}
        Assert-BoundedRecoveryArtifact $artifact 16777216
        $object=Get-RecoveryObject $path
        $record=New-CRecoveryRecord 'Firewall' $path $object.Identity @{CapturedPolicyArtifact=$artifact} $null
        $record.Artifact=$artifact;Write-RecoveryRecord $record
        $record=Copy-CRecoveryRecord $record;$record.Revision++;$record.State='Applied';$record.AppliedObservation=@{SavedArtifact=$artifact}
        Write-RecoveryRecord $record
    }
    $State.BackupDir=$OutDir
    foreach($target in $BackupPaths){$null=Invoke-Step "capture content original $target" {Save-ContentOriginal $target}}
}
# Start of run: close every inbound port except RDP, $KeepOpenTcp and DHCP. Service ports reopen in Open-ServicePorts at the end.
# Purging old rules and switching to default-block are separate decisions: skipping one for safety doesn't require skipping the other.
function Set-FirewallLockdown {
    $plan=$State.Preconditions.RecoveryPlan;$plan.ProfileOperations=@();$plan.StartupDecisionEstablished=$false
    $State.Purge=$false;$State.Enable=$false
    $listeners=Get-ListeningPorts;$policy=Get-FirewallSnapshot
    if($listeners.Status -ne 'Complete' -or $policy.Status -ne 'Complete'){throw 'Startup firewall observations incomplete'}
    $backup=Test-FirewallBackupReady
    $purge=(-not $State.IsDC -and $backup)
    $covered=@(@($AllowTcp)+@(Get-KeepPorts) | ForEach-Object {"TCP:$_"})+@($AllowUdp | ForEach-Object {"UDP:$_"})
    if(-not $purge){$existing=Get-InboundAllowPorts;if($existing.Status -ne 'Complete'){throw 'Allow discovery failed'};$covered+=@($existing.Items)}
    $State.Uncovered=@($listeners.Items | Where-Object {$covered -notcontains "$($_.Proto):$($_.Port)"})
    if($State.IsDC){Write-Log 'DC: existing rules and defaults are preserved.'}
    if(-not $backup){Write-Log 'No completed firewall backup: purge prohibited; default-block has separate authorization.'}
    foreach($listener in $State.Uncovered){Write-Log "Uncovered listener: $($listener.Proto):$($listener.Port)"}
    $enable=$true
    if($State.Uncovered.Count -or ($State.IsDC -and @($policy.Items[0].Profiles | Where-Object {[string]$_.Enabled -eq 'False'}).Count)){
        if(-not $DryRun){$enable=((Read-Host 'Enable lockdown despite uncovered listeners or disabled DC profiles? y/N') -eq 'y')}
    }
    if(-not $enable){Write-Log 'Startup firewall changes declined.';return}
    $controls=$true
    foreach($port in @(Get-KeepPorts)){if(-not (Add-Rule 'Keep' 'TCP' $port)){$controls=$false}}
    if(-not $State.IsDC){foreach($pair in @(@(68,67),@(546,547))){if(-not (Add-DhcpControl $pair[0] $pair[1])){$controls=$false}}}
    if($DryRun){Write-Log 'WOULD: change only firewall operations whose effective controls and policy can be verified';return}
    if(-not $controls){throw 'Required controls failed; no purge/profile authority'}
    # Consent may block for arbitrary time. Recheck effective controls after it.
    foreach($port in @(Get-KeepPorts)){Assert-EffectiveControl "HPCC4-Keep-TCP-$port" 'TCP' $port}
    $plan.StartupDecisionEstablished=$true
    $plan.ProfileOperations=@('Domain','Private','Public' | ForEach-Object {@{Profile=$_;Enabled=$true}})
    $State.Enable=$true
    if($purge){Remove-InboundRules -All;$State.Purge=($State.Failures.Count -eq 0)}
    Enable-Firewall -BlockInbound:(-not $State.IsDC)
}
# Deletes local accounts that aren't authorized. Always kept: built-ins (ID < 1000: Administrator even if renamed, Guest, etc.),
# you, $AuthorizedUsers, $ExcludeUsers, and accounts that services, app pools or tasks run as. Deleting can't be undone,
# so each account's SID and groups are printed first, in case you need to recreate it.
function Remove-UnauthorizedUsers {
    if ($State.IsDC -isnot [bool] -or $State.IsDC) { Write-Log 'Skipping account removal: role unavailable or DC.'; return }
    if (@($AuthorizedUsers).Count -eq 0) { Write-Log 'Skipping account removal: AuthorizedUsers is empty.'; return }
    $read = @(Get-AccountSnapshot)
    if ($read.Count -ne 1 -or $read[0].Status -ne 'Complete') { Add-RunFailure -Stage Accounts -Operation Delete -Detail 'Discovery incomplete'; return }
    foreach ($name in $AuthorizedUsers) {
        if ($name -isnot [string] -or [string]::IsNullOrWhiteSpace($name) -or $name -ne $name.Trim() -or $name -match '[\\/\x00-\x1f"\[\]:;|=,+*?<>@]' -or @($read[0].Items | Where-Object { $_.Name -eq $name }).Count -ne 1) {
            Add-RunFailure -Stage Accounts -Operation Delete -Detail 'Invalid or unresolved AuthorizedUsers entry'; return
        }
    }
    $approved = @($read[0].Items | Where-Object { -not $_.Protected -and [long]($_.SID -split '-')[-1] -ge 1000 -and $AuthorizedUsers -notcontains $_.Name } | Select-Object SID,Name,Enabled)
    if (-not $approved.Count) { Write-Log 'No unauthorized local accounts found.'; return }
    Write-Log "UNAUTHORIZED accounts to DELETE: $($approved.Name -join ', ')"
    if ($DryRun) { Write-Log 'WOULD: delete the accounts above'; return }
    $consent = Read-Host 'DELETE these accounts permanently? y/N'
    $approved = @(Test-ApprovedAccountSet -Approved $approved -Operation Delete)
    if ($consent -ne 'y') { return }
    foreach ($u in $approved) {
        Write-Log "Deleting $($u.Name) (SID $($u.SID)); original SID cannot be recreated."
        if (Invoke-Step "delete account $($u.Name)" {
            if (@(Test-ApprovedAccountSet -Approved @($u) -Operation Delete).Count -ne 1) { throw 'Account authorization refused' }
            Remove-LocalUser -SID $u.SID -ErrorAction Stop
        }) { $State.Deleted += $u.Name }
    }
}
function Set-LocalPasswords {
    if ($State.IsDC -isnot [bool] -or $State.IsDC) { Write-Log 'Skipping passwords: role unavailable or DC.'; return }
    $read = @(Get-AccountSnapshot)
    if ($read.Count -ne 1 -or $read[0].Status -ne 'Complete') { Add-RunFailure -Stage Accounts -Operation Password -Detail 'Discovery incomplete'; return }
    $approved = @($read[0].Items | Where-Object { $_.Enabled -and -not $_.Protected } | Select-Object SID,Name,Enabled)
    if (-not $approved.Count) { Write-Log 'No password targets.'; return }
    Write-Log "Password targets: $($approved.Name -join ', ')"
    if ($DryRun) { Write-Log 'WOULD: change passwords for targets above'; return }
    $consent = Read-Host 'Change these passwords? y/N'
    $approved = @(Test-ApprovedAccountSet -Approved $approved -Operation Password)
    if ($consent -ne 'y' -or -not $approved.Count) { return }
    $pw = $null; $changed = @()
    try {
        for ($i = 0; $i -lt 3 -and $null -eq $pw; $i++) {
            $s1 = $s2 = $null
            try {
                $s1 = Read-Host 'New password (blank to skip)' -AsSecureString
                $approved = @(Test-ApprovedAccountSet -Approved $approved -Operation Password)
                if (-not $approved.Count -or $s1.Length -eq 0) { return }
                $s2 = Read-Host 'Confirm password' -AsSecureString
                $approved = @(Test-ApprovedAccountSet -Approved $approved -Operation Password)
                if (-not $approved.Count) { return }
                if (Test-AccountSecretEqual -Left $s1 -Right $s2) { $pw = $s1; $s1 = $null }
                else { Write-Log 'Passwords did not match, try again.' }
            } finally {
                if ($null -ne $s2 -and -not [object]::ReferenceEquals($s1,$s2) -and -not [object]::ReferenceEquals($pw,$s2)) { $s2.Dispose() }
                if ($null -ne $s1) { $s1.Dispose() }
            }
        }
        if ($null -eq $pw) { Write-Log 'Password entry failed after 3 tries.'; return }
        foreach ($u in $approved) {
            if (Invoke-Step "password $($u.Name)" {
                if (@(Test-ApprovedAccountSet -Approved @($u) -Operation Password).Count -ne 1) { throw 'Account authorization refused' }
                Set-LocalUser -SID $u.SID -Password $pw -ErrorAction Stop
            }) { $State.Changed += $u.Name; $changed += $u.Name }
        }
    } finally { if ($null -ne $pw) { $pw.Dispose() } }
    Write-Log "Changed accounts: $($changed -join ', ')"
    if ($changed.Count) { Write-Log 'SUBMIT PASSWORD CHANGES TO THE SCOREBOARD; policy failures can leave partial changes.' }
}
# ---- Extra services ----
# Stops + disables only the services in $DisableServices (extras beyond the STIG GPO's baseline). Empty by default = no-op.
function Disable-ExtraServices {
    $approved=@($DisableServices | Select-Object -Unique)
    foreach ($name in $approved) {
        if ($name -isnot [string] -or -not $name -or $name -match '[\x00-\x1f*?\[\]\\/]') { Add-RunFailure 'Services' 'Validate' 'LiteralServiceNameRequired'; continue }
        try {
            $services=@(Get-Service -Name $name -ErrorAction Stop)
            if ($services.Count -ne 1 -or $services[0].Name -ine $name) { throw 'Service identity ambiguous' }
            $service=$services[0]
            $dependents=@($service.DependentServices | Where-Object { $_.Status -ne 'Stopped' })
            if (@($dependents | Where-Object { $approved -notcontains $_.Name }).Count) { throw 'Unapproved running dependent service' }
            # No Force: SCM must refuse implicit dependent expansion. Each named
            # dependent is independently processed by this same approved list.
            $null=Invoke-Step "stop service $name" { Stop-Service -InputObject $service -ErrorAction Stop }
            if (Invoke-Step "disable service $name" { Set-Service -InputObject $service -StartupType Disabled -ErrorAction Stop }) { $State.ServicesDisabled += $name }
        } catch { if (Test-RunCancellation $_) { throw }; Add-RunFailure 'Services' $name $_.Exception.GetType().Name }
    }
}
# ---- Persistence sweep (REPORT ONLY - never removes anything) ----
# A command is flagged suspicious if its exe (or the full command line) runs from a user-writable/temp path, is
# unsigned, or looks encoded/hidden (-enc*, FromBase64String, -windowstyle hidden, iex/Invoke-Expression).
function Test-SuspiciousPath {
    param([string]$Cmd)
    if (-not $Cmd) { return $false }
    $exe = if ($Cmd -match '^\s*"([^"]+)"') { $Matches[1] } else { ($Cmd -split '\s+')[0] }
    $writable = '(?i)\\(Users|AppData|Temp|ProgramData|Public|Downloads)\\'
    if ($exe -match $writable -or $Cmd -match $writable) { return $true }
    if ($Cmd -match '(?i)(^|\s)-e(c|n(c\w*)?)?(\s|$)' -or $Cmd -match '(?i)FromBase64String' -or $Cmd -match '(?i)-w(indowstyle)?\s+hidden' -or $Cmd -match '(?i)\b(iex|invoke-expression)\b') { return $true }
    if (Test-Path $exe -ErrorAction SilentlyContinue) { try { if ((Get-AuthenticodeSignature $exe).Status -ne 'Valid') { return $true } } catch {} }
    return $false
}
# Registry keys holding one autostart command per VALUE. Run/RunOnce: every value (minus PowerShell's own synthetic
# ones). The rest: only the named values that are actual hijack points. One table, one loop, instead of one block per key.
$script:PersistenceRegistrySources = @(
    @{ Type = 'Run'; Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
    @{ Type = 'Run'; Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
    @{ Type = 'Run'; Key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
    @{ Type = 'Run'; Key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
    @{ Type = 'Winlogon'; Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Values = 'Shell', 'Userinit' },
    @{ Type = 'AppInit'; Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; Values = @('AppInit_DLLs') },
    @{ Type = 'AppCert'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'; Values = @() },
    @{ Type = 'LSA-Package'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Values = 'Security Packages', 'Notification Packages', 'Authentication Packages' }
)
$script:PsSyntheticProps = 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider'
# Lists everything in $PersistenceRegistrySources, IFEO debugger hijacks, Active Setup StubPath, EVERY scheduled task
# (including under \Microsoft\*, where masquerading persistence hides), off-path auto services (including svchost
# ServiceDll hijacks), WMI subscriptions, every local user's Startup folder, and any currently logged-on OTHER user's
# Run/RunOnce (via their already-loaded hive under HKEY_USERS - nothing is mounted or unmounted by this script).
function Get-PersistenceReport {
    $sources=@();$found=@();$mySid=$null;$identity=$null
    try{$identity=Get-CurrentWindowsIdentity;$mySid=$identity.User.Value}
    catch{if(Test-RunCancellation $_){throw};$sources+=@{Name='CurrentToken';Result=(New-ReadResult 'Failed' @() @('TokenObservationFailed'))}}
    finally{if($null -ne $identity){$identity.Dispose()}}
    foreach($source in $script:PersistenceRegistrySources){
        $read=Read-PersistenceSource $source.Key {Get-PersistenceRegistryRows $source.Key $source.Type @($source.Values)}
        $sources+=@{Name=$source.Key;Result=$read};$found+=@($read.Items)
    }
    $read=Read-PersistenceSource 'LoadedUserHives' {
        foreach($hive in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop)){
            if($hive.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' -and $hive.PSChildName -ne $mySid){
                foreach($sub in 'Run','RunOnce'){
                    $key="Registry::HKEY_USERS\$($hive.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\$sub"
                    if(Test-Path -LiteralPath $key){Get-PersistenceRegistryRows $key 'UserRun'}
                }
            }
        }
    };$sources+=@{Name='LoadedUserHives';Result=$read};$found+=@($read.Items)
    foreach($branch in @(@{Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options';Name='Debugger';Type='IFEO'},@{Path='HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components';Name='StubPath';Type='ActiveSetup'})){
        $read=Read-PersistenceSource $branch.Type {foreach($item in @(Get-ChildItem -LiteralPath $branch.Path -ErrorAction Stop)){Get-PersistenceRegistryRows $item.PSPath $branch.Type @($branch.Name)}}
        $sources+=@{Name=$branch.Type;Result=$read};$found+=@($read.Items)
    }
    $read=Read-PersistenceSource 'Tasks' {
        foreach($task in @(Get-ScheduledTask -ErrorAction Stop)){
            $index=0;foreach($action in @($task.Actions)){
                foreach($property in 'Execute','Arguments','WorkingDirectory','ClassId','Data'){
                    if($null -ne $action.$property){New-PersistenceRows 'TaskAction' "$($task.TaskPath)$($task.TaskName)|$index|$property" $action.$property}
                };$index++
            }
        }
    };$sources+=@{Name='Tasks';Result=$read};$found+=@($read.Items)
    $read=Read-PersistenceSource 'Services' {
        foreach($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)){
            New-PersistenceRows 'Service' $service.Name @($service.PathName,$service.StartName,$service.StartMode)
            $key="HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)\Parameters"
            if(Test-Path -LiteralPath $key){Get-PersistenceRegistryRows $key ('ServiceDll|'+$service.Name) @('ServiceDll','ServiceMain','ServiceDllUnloadOnStop')}
        }
    };$sources+=@{Name='Services';Result=$read};$found+=@($read.Items)
    foreach($class in '__EventFilter','__FilterToConsumerBinding','CommandLineEventConsumer','ActiveScriptEventConsumer'){
        $read=Read-PersistenceSource $class {
            foreach($entry in @(Get-CimInstance -Namespace 'root\subscription' -ClassName $class -ErrorAction Stop)){
                foreach($property in 'Name','Filter','Consumer','Query','QueryLanguage','EventNamespace','ExecutablePath','CommandLineTemplate','WorkingDirectory','ScriptText','ScriptFileName','ScriptingEngine'){
                    if($null -ne $entry.$property){New-PersistenceRows $class "$($entry.Name)|$property" $entry.$property}
                }
            }
        };$sources+=@{Name=$class;Result=$read};$found+=@($read.Items)
    }
    $read=Read-PersistenceSource 'StartupFolders' {
        $profileRoot=Join-Path ([IO.Path]::GetPathRoot((Get-OsSystemDirectory))) 'Users'
        $dirs=@(Get-ChildItem -LiteralPath $profileRoot -Directory -ErrorAction Stop | ForEach-Object {Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'})
        $dirs+=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Microsoft\Windows\Start Menu\Programs\Startup'
        foreach($dir in $dirs){if(Test-Path -LiteralPath $dir){foreach($item in @(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction Stop)){
            New-PersistenceRows 'StartupFile' $item.FullName @($item.FullName)
            if($item.Extension -ieq '.lnk'){New-PersistenceRows 'StartupLink' $item.FullName @(Get-StartupLinkTarget $item.FullName)}
        }}}
    };$sources+=@{Name='StartupFolders';Result=$read};$found+=@($read.Items)
    $State.Persistence=$found;$State.PersistenceSources=$sources
    $incomplete=@($sources | Where-Object {$_.Result.Status -notin 'Complete','Absent'})
    if($incomplete.Count){Add-RunFailure 'Persistence' 'Coverage' 'OneOrMoreSourcesIncomplete'}
    Write-Log "Persistence: $($found.Count) payload/member rows; $($incomplete.Count) incomplete sources. Nothing executed or removed."
    foreach($row in @($found | Where-Object Suspicious)){Write-Log "Suspicious $($row.Type): $($row.Name) -> $($row.Command)"}
    $null=Invoke-Step 'write protected persistence report' {
        Lock-AdminOnlyAcl $OutDir
        $report=Join-Path $OutDir ('persistence-'+$State.RunId+'.txt')
        # Structured lines retain full strings; table-width truncation is avoided.
        $content=@('Scope: loaded user hives, listed autostart sources; polling/scan is not exhaustive or atomic.')
        foreach($source in $sources){$content+=(ConvertTo-Json -InputObject @{Source=$source.Name;Status=$source.Result.Status;Errors=@($source.Result.Errors)} -Compress -Depth 6)}
        foreach($row in $found){$content+=(ConvertTo-Json -InputObject $row -Compress -Depth 6)}
        Write-RecoveryBytes $report ([Text.Encoding]::UTF8.GetBytes(($content -join [Environment]::NewLine)))
        Assert-TrustedPath $report -Confidential;$State.PersistenceReport=$report
    }
}
# ---- DoD STIG GPO ----
# Imports only the validated ordered operator selections after a checked local-policy backup.
# Import/refresh success is distinct from effective policy and final access-control verification.
function Install-DodGpo {
    if (-not $DodGpoDir) { Write-Log 'DoD GPO not configured; no STIG package applied.'; return }
    foreach ($dependency in 'Get-CanonicalFilePath','Assert-NativeApproval','Invoke-NativeCommand','Get-TrustedNativePath','Save-LocalPolicyRecoveryRecord','Get-PostGpoPolicyObservation','Add-RunFailure') {
        if (-not (Get-Command $dependency -CommandType Function -ErrorAction SilentlyContinue)) { throw "GPO integration dependency unavailable: $dependency" }
    }
    $selected = @(Get-DodGpoSelection -Root $DodGpoDir -Selection $DodGpoSelection)
    $lgpo = Get-CanonicalFilePath $(if ($State.AcceptedLgpoPath) { $State.AcceptedLgpoPath } elseif ($LgpoExe) { $LgpoExe } else { throw 'No accepted LGPO this run' }) -MustExist
    Assert-NativeApproval -ExecutablePath $lgpo
    $approval = $State.Preconditions.NativeApprovals[$lgpo]
    if (-not $approval -or $approval.Role -cne 'LGPO' -or $approval.Digest -notmatch '^[a-fA-F0-9]{64}$' -or
        $approval.TrustPolicy -notin 'PinnedDigest','ValidSignature','ExpectedSigner' -or -not $approval.ResourceIdentity) { throw 'GPO requires registered trusted LGPO role' }
    $State.GpoOutcomes = @(); $State.GpoRefresh = 'NotAttempted'; $State.GpoObservation = $null
    if ($DryRun) { foreach ($item in $selected) { Write-Log "WOULD import approved $($item.Package) $($item.Version) $($item.Role): $($item.Path)" }; return }
    $selected=@(Stage-DodGpoInputs $selected)
    $backup = Save-LocalPolicyRecoveryRecord -LgpoPath $lgpo
    if ($null -eq $backup -or $backup.Status -ne 'Complete' -or @($backup.Items).Count -ne 1) { throw 'Checked local-policy backup unavailable' }
    $record = $backup.Items[0]
    if ($record -isnot [hashtable] -or $record.SchemaVersion -ne 1 -or $record.Kind -ne 'LocalPolicy' -or $record.State -ne 'Applied' -or
        -not $record.ResourceIdentity -or $record.Artifact -isnot [hashtable] -or $record.Artifact.Complete -isnot [bool] -or -not $record.Artifact.Complete -or
        $record.Artifact.Digest -notmatch '^[a-fA-F0-9]{64}$' -or -not $record.Artifact.CanonicalPath) { throw 'Local-policy backup record is incomplete/unprotected' }
    Test-PolicyBackupManifest $record
    $succeeded = 0
    foreach ($item in $selected) {
        # Re-read all approved bytes immediately before each use. B independently rechecks executable trust.
        $ok = Invoke-Step "LGPO import $($item.Package) $($item.Version) $($item.Role)" {
            $null = Get-DodGpoSelection -Root $State.GpoInputRoot -Selection @($item.Approval)
            $null = Invoke-NativeCommand -ExecutablePath $lgpo -Arguments @('/g', $item.Path) -SuccessExitCodes @(0)
        }
        $State.GpoOutcomes += [pscustomobject]@{ Path=$item.Path; Package=$item.Package; Version=$item.Version; Role=$item.Role; Imported=[bool]$ok }
        if ($ok) { $State.GpoApplied += $item.Path; $succeeded++ }
    }
    if ($succeeded) {
        $refresh = Invoke-Step 'gpupdate /force' {
            $gpupdate = Get-TrustedNativePath -Name 'gpupdate.exe'
            $null = Invoke-NativeCommand -ExecutablePath $gpupdate -Arguments @('/force') -SuccessExitCodes @(0)
        }
        $State.GpoRefresh = if ($refresh) { 'Complete' } else { 'Failed' }
        $State.GpoObservation = Get-PostGpoPolicyObservation
        if ($null -eq $State.GpoObservation -or $State.GpoObservation.Status -ne 'Complete') { Add-RunFailure -Stage 'GPO' -Operation 'ResultantPolicy' -Detail 'Effective policy observation incomplete' }
    }
    Write-Log 'GPO import status is not effective-policy or access proof. Original backups retained; local-policy/firewall backups do not provide universal STIG rollback.'
}
# Copies/downloads the archive into protected staging and extracts bounded approved inputs.
function Expand-ToolsZip {
    param([string]$Destination)
    if($DryRun){Write-Log 'WOULD: stage and validate selected tools archive';return $false}
    $zip=Join-Path ([IO.Path]::GetDirectoryName($Destination)) 'package.zip'
    if($ToolsZip -match '^https://'){
        if(-not(Invoke-Step 'download tools archive' {Invoke-WebRequest -Uri $ToolsZip -OutFile $zip -UseBasicParsing -ErrorAction Stop;Assert-TrustedPath $zip -Confidential})){return $false}
    }elseif($ToolsZip -match '^[a-zA-Z]:[\\/]'){
        if(-not(Invoke-Step 'stage local tools archive' {Copy-ProtectedInput $ToolsZip $zip})){return $false}
    }else{Add-RunFailure 'Tools' 'Archive' 'HttpsOrLocalArchiveRequired';return $false}
    $digest=Get-NativeFileDigest $zip
    if($ToolsZipSha256 -and $digest -ine $ToolsZipSha256){$State.HashChecked='MISMATCH - rejected';Add-RunFailure 'Tools' 'Archive' 'DigestMismatch';return $false}
    $State.HashChecked=if($ToolsZipSha256){'ok'}else{'not set'}
    return (Invoke-Step 'extract bounded protected tools archive' {Expand-ProtectedArchive $zip $Destination})
}
function Install-Tools {
    $State.ToolsInstalled=$false;$State.AvInstaller='';$State.ToolReadiness=@{Archive='NotRequested';AV='NotRequested';Sysmon='NotRequested';LGPO='NotRequested'}
    if($DryRun){Write-Log 'WOULD: stage requested packages, validate roles, publish PATH/EULA only for accepted tools';return}
    if(-not $ToolsZip -and -not $AvInstallerUrl -and -not $LgpoExe){if($InstallSysmon){Add-RunFailure 'Tools' 'Sysmon' 'ExplicitAcceptedPackageRequired'};return}
    Lock-AdminOnlyAcl $OutDir
    Initialize-OwnedToolDirectory $ToolsDir
    $roleRoot=Join-Path $ToolsDir $State.RunId;Initialize-OwnedToolDirectory $roleRoot
    $priorTls=Get-TlsProtocol;$primary=$null
    try{
        Set-TlsProtocol ($priorTls -bor [Net.SecurityProtocolType]::Tls12)
        $local:ProgressPreference='SilentlyContinue'
        if($ToolsZip){
            $State.ToolReadiness.Archive='Failed';$package=Join-Path $roleRoot 'archive';Initialize-ProtectedDirectory $package
            if(Expand-ToolsZip $package){
                $State.ToolReadiness.Archive='Complete';$State.ToolsInstalled=$true;$State.AcceptedToolsDir=$package
                if($DodGpoDir -and -not $LgpoExe){$archiveLgpo=Join-Path $package 'LGPO.exe';$State.AcceptedLgpoPath=Approve-RoleExecutable $archiveLgpo 'LGPO' -Pinned:([bool]$ToolsZipSha256);$State.ToolReadiness.LGPO='Complete'}
                if($InstallSysmon){Install-AcceptedSysmon $package -Pinned:([bool]$ToolsZipSha256)}
                # The current process PATH is intentionally unchanged.
                Set-OwnedRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' 'Path' 'AppendPath' $package
                Set-OwnedRegistryValue 'HKCU:\Software\Sysinternals' 'EulaAccepted' 'DWord' 1
            }
        }
        if($LgpoExe -and (-not $ToolsZip -or $State.ToolReadiness.Archive -eq 'Complete')){
            $stagedLgpo=Join-Path $roleRoot 'lgpo.exe';Copy-ProtectedInput $LgpoExe $stagedLgpo;$State.AcceptedLgpoPath=Approve-RoleExecutable $stagedLgpo 'LGPO';$State.ToolReadiness.LGPO='Complete'
        }
        if($AvInstallerUrl){
            $State.ToolReadiness.AV='Failed';$av=Join-Path $roleRoot 'av.exe'
            if($AvInstallerUrl -notmatch '^https://'){Add-RunFailure 'Tools' 'AV' 'HttpsRequired'}
            elseif(Invoke-Step 'download and approve AV installer' {Invoke-WebRequest -Uri $AvInstallerUrl -OutFile $av -UseBasicParsing -ErrorAction Stop;$null=Approve-RoleExecutable $av 'AV'}){$State.AvInstaller=$av;$State.ToolReadiness.AV='Complete'}
        }
    }catch{$primary=$_;if(Test-RunCancellation $_){$State.Cancelled=$true};throw}
    finally{
        try{Set-TlsProtocol $priorTls}catch{Add-RunFailure 'Tools' 'RestoreTls' $_.Exception.GetType().Name;if($primary -and (Test-RunCancellation $primary)){throw $primary};if(Test-RunCancellation $_){$State.Cancelled=$true;if($primary){Add-RunFailure 'Tools' 'Package' $primary.Exception.GetType().Name};throw};if($primary){throw $primary};throw}
    }
}

# True only if Everyone is specifically denied the Write right this script's own Lock-Paths applies - not just any
# unrelated pre-existing Deny-Everyone ACE (e.g. a Deny-Read from some other policy), which would give a false "already locked".
function Test-EveryoneDeny {
    param([string]$Path)
    $canonical=Get-CanonicalFilePath $Path -MustExist
    $object=Get-RecoveryObject $canonical
    # Never turn unknown reads into unlocked. Watcher I must catch/display Unknown.
    $needed=if ($object.Directory) { 0x10156 } else { 0x10116 }
    $mask=0
    foreach ($rule in $object.Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Deny' -and $rule.IdentityReference.Value -eq 'S-1-1-0' -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { $mask=$mask -bor [int]$rule.FileSystemRights }
    }
    if ($object.Directory) { throw 'Root ACL cannot certify descendant deny scope' }
    [bool](($mask -band $needed) -eq $needed)
}
# Lock captures exact original ACL/attributes before applying the intended descriptor.
# Restoration still requires verified identity and current-applied-state observations.
function Lock-Paths {
    foreach ($target in $LockPaths) {
        if ($DryRun) { Write-Log "WOULD: save and lock exact file $target"; continue }
        try {
            $read=Save-AclRecoveryRecord $target
            if ($read.Status -ne 'Complete' -or $read.Items.Count -ne 1) { throw 'Committed complete original required' }
            $record=$read.Items[0]
            $current=Get-CFileObservation $record.CanonicalPath
            if ($record.State -eq 'Applied' -and (Test-DataEqual $current $record.AppliedObservation)) { $State.Locked += $record.CanonicalPath; continue }
            if ($record.State -ne 'Intent' -or -not (Test-DataEqual $current $record.Prior)) { throw 'Interrupted or conflicting lock requires recovery' }
            Set-CFileAttributes $record.CanonicalPath $record.IntendedState.Attributes
            $intermediate=@{ Identity=$record.ResourceIdentity; Sddl=$record.Prior.Sddl; Attributes=$record.IntendedState.Attributes }
            if (-not (Test-DataEqual (Get-CFileObservation $record.CanonicalPath) $intermediate)) { throw 'Attribute mutation observation conflict' }
            Set-CFileDescriptor $record.CanonicalPath $record.IntendedState.Sddl
            $observed=Get-CFileObservation $record.CanonicalPath
            if (-not (Test-DataEqual $observed $record.IntendedState) -or -not (Test-EveryoneDeny $record.CanonicalPath)) { throw 'Lock observation incomplete' }
            $updated=Copy-CRecoveryRecord $record
            $updated.Revision++; $updated.State='Applied'; $updated.AppliedObservation=$observed; $updated.ChangedByRun=$true
            Write-RecoveryRecord $updated
            $State.Locked += $record.CanonicalPath
        } catch { if (Test-RunCancellation $_) { throw }; Add-RunFailure 'Acl' 'Lock' $_.Exception.Message }
    }
}
# Unlock restores validated exact originals and records outcomes without discarding evidence.
function Unlock-Paths {
    if ($DryRun) { Write-Log 'WOULD: restore only exact validated recorded ACL resources'; return }
    $read=Read-RecoveryRecords $OutDir 'Acl'
    if ($read.Status -notin 'Complete','Absent') { throw 'Recovery metadata incomplete; no restore attempted' }
    foreach ($record in @($read.Items | Where-Object { $_.State -ne 'Restored' })) { $null=Restore-AclRecoveryRecord $record }
    # Never import legacy sidecars or erase original metadata after failure.
}
# Eligible final recovery attempts the frozen finite port/profile operations.
function Open-ServicePorts {
    Invoke-FiniteRecovery
}
function Write-Summary {
    Write-Log "Backup: $($script:State.BackupDir) | Uncovered ports: $($script:State.Uncovered.Count) | Old inbound rules removed: $($script:State.Purge) | Firewall on: $($script:State.FirewallOn)"
    Write-Log "Rules added: $($script:State.RulesAdded -join ', ') | Blocks refused: $($script:State.BlocksRefused -join ', ') | Accounts deleted: $($script:State.Deleted -join ', ') | Passwords changed: $($script:State.Changed -join ', ')"
    Write-Log "Extra services disabled: $($script:State.ServicesDisabled -join ', ')"
    Write-Log "Persistence entries: $($script:State.Persistence.Count) ($(@($script:State.Persistence | Where-Object { $_.Suspicious }).Count) suspicious) | DoD GPOs applied: $($script:State.GpoApplied.Count)"
    Write-Log "Tools installed: $($script:State.ToolsInstalled) | Hash check: $($script:State.HashChecked) | AV installer: $($script:State.AvInstaller) | Locked: $($script:State.Locked -join ', ') | Failures: $($script:State.Failures -join ', ')"
    if (-not $script:State.GpoApplied.Count) { Write-Log 'No DoD package imported this run; verify existing and effective policy with gpo-verification-checklist.md.' }
}
# Optional cleanup reports independent history/log outcomes and schedules exact-file removal.
function Invoke-Cleanup {
    if($DryRun){Write-Log 'WOULD: clear current session history, selected logs, schedule verified exact-file removal';return}
    # Independent outcomes: an unavailable memory API must not suppress disk or
    # session history attempts. Never restore SaveAtExit after clearing.
    $null=Invoke-Step 'disable history saving' {
        if(Get-Command Get-PSReadLineOption -ErrorAction SilentlyContinue){Set-PSReadLineOption -HistorySaveStyle SaveNothing -ErrorAction Stop}
    }
    $null=Invoke-Step 'clear PSReadLine memory' {if(Get-Command Get-PSReadLineOption -ErrorAction SilentlyContinue){Clear-CPSReadLineMemory}}
    $null=Invoke-Step 'clear PSReadLine disk history' {
        if(Get-Command Get-PSReadLineOption -ErrorAction SilentlyContinue){$option=Get-PSReadLineOption -ErrorAction Stop;if($option.HistorySavePath){Remove-CHistoryFile $option.HistorySavePath}}
    }
    $null=Invoke-Step 'clear current PowerShell session history' {Clear-History -ErrorAction Stop}
    try{$logs=@(Get-CCleanupLogs)}catch{if(Test-RunCancellation $_){throw};Add-RunFailure 'Cleanup' 'ListLogs' $_.Exception.GetType().Name;$logs=@()}
    foreach($log in $logs){$null=Invoke-Step "clear event log $log" {Clear-EventLog $log}}
    if($script:DeploymentIdentity){$null=Invoke-Step 'schedule exact deployed-file removal' {$scheduled=Start-DeferredScriptRemoval $script:DeploymentIdentity.Path;if(-not $scheduled){throw 'Removal not scheduled'};Write-Log 'Removal scheduled; deletion completion is unknown.'}}
    else{Write-Log 'Deployment identity unavailable: remove the deployed script manually.'}
    Write-Log 'Other sessions, copies, protected recovery records and external traces remain.'
}
function Assert-CAclRecord {
    param([hashtable]$Record)
    Assert-RecoveryRecord $Record
    if ($Record.Kind -ne 'Acl' -or $Record.Ownership -ne 'Preexisting' -or $Record.ResourceId -cne $Record.CanonicalPath.ToUpperInvariant()) { throw 'Unsupported ACL record' }
    foreach ($observation in @($Record.Prior,$Record.IntendedState)) {
        if ($observation -isnot [hashtable] -or $observation.Count -ne 3 -or $observation.Sddl -isnot [string] -or -not $observation.Sddl -or $observation.Attributes -isnot [int] -or $observation.Identity -isnot [hashtable] -or -not (Test-DataEqual $observation.Identity $Record.ResourceIdentity)) { throw 'Missing exact original/intended ACL, attributes or identity' }
    }
    if ($Record.ResourceIdentity.Policy -ne 'VolumeFileId' -or -not $Record.ResourceIdentity.Value) { throw 'Unsupported ACL identity' }
    if ($Record.State -eq 'Applied' -and -not (Test-DataEqual $Record.AppliedObservation $Record.IntendedState)) { throw 'Applied ACL observation mismatch' }
    if ($Record.State -eq 'RestoreFailed') {
        $intermediate=@{ Identity=$Record.ResourceIdentity; Sddl=$Record.Prior.Sddl; Attributes=$Record.IntendedState.Attributes }
        if (-not (Test-DataEqual $Record.AppliedObservation $intermediate)) { throw 'Unverified restore intermediate; manual recovery required' }
    }
}

function Restore-AclRecoveryRecord {
    param([hashtable]$Record)
    if ($DryRun) { return $false }
    try {
        $read=Get-AclRecoveryRecord $Record.CanonicalPath
        if ($read.Status -ne 'Complete' -or $read.Items.Count -ne 1 -or -not (Test-DataEqual $read.Items[0] $Record)) { throw 'Stale or unavailable original' }
        Assert-CAclRecord $Record
        $current=Get-CFileObservation $Record.CanonicalPath
        if (-not (Test-DataEqual $current.Identity $Record.ResourceIdentity)) { throw 'Resource identity conflict' }
        if ($Record.State -eq 'Intent') {
            $disposition=Get-IntentRecoveryDisposition $Record $current.Identity $current
            if ($disposition -eq 'Unknown') { throw 'Unrecorded crash gap; manual recovery required' }
            if ($disposition -eq 'NoChange') {
                $done=Copy-CRecoveryRecord $Record
                $done.Revision++; $done.State='Restored'; $done.AppliedObservation=$current
                Write-RecoveryRecord $done
                return $true
            }
        } elseif ($Record.State -notin 'Applied','RestoreFailed' -or -not (Test-DataEqual $current $Record.AppliedObservation)) { throw 'Applied observation conflict; original retained' }
        $intermediate=@{ Identity=$Record.ResourceIdentity; Sddl=$Record.Prior.Sddl; Attributes=$Record.IntendedState.Attributes }
        $working=Copy-CRecoveryRecord $Record
        if ($Record.State -ne 'RestoreFailed') {
            Set-CFileDescriptor $Record.CanonicalPath $Record.Prior.Sddl
            if (-not (Test-DataEqual (Get-CFileObservation $Record.CanonicalPath) $intermediate)) { throw 'Intermediate observation failed; manual recovery required' }
            $working.Revision++; $working.State='RestoreFailed'; $working.AppliedObservation=$intermediate
            # Publication must succeed before the second restoration step. A
            # crash or failed publication cannot adopt arbitrary current state.
            Write-RecoveryRecord $working
        }
        if (-not (Test-DataEqual (Get-CFileObservation $Record.CanonicalPath) $intermediate)) { throw 'Intermediate changed; recovery conflict' }
        Set-CFileAttributes $Record.CanonicalPath $Record.Prior.Attributes
        $final=Get-CFileObservation $Record.CanonicalPath
        if (-not (Test-DataEqual $final $Record.Prior)) { throw 'Original restoration not observed' }
        $done=Copy-CRecoveryRecord $working
        $done.Revision++; $done.State='Restored'; $done.AppliedObservation=$final
        Write-RecoveryRecord $done
        return $true
    } catch { if (Test-RunCancellation $_) { throw }; Add-RunFailure 'Acl' 'Restore' $_.Exception.Message; return $false }
}

function Get-CCleanupLogs {
    Get-WinEvent -ListLog * -ErrorAction Stop | ForEach-Object { $_.LogName }
}

function Get-AclRecoveryRecord {
    param([string]$Target)
    try {
        $canonical=Get-CanonicalFilePath $Target -MustExist
        $read=Read-RecoveryRecords $OutDir 'Acl'
        if ($read.Status -notin 'Complete','Absent') { return New-ReadResult 'Failed' @() @('UnreadableAclMetadata') }
        $records=@($read.Items | Where-Object { $_.CanonicalPath -ieq $canonical -and $_.State -ne 'Restored' })
        if ($records.Count -gt 1) { throw 'Duplicate ACL original' }
        if (-not $records.Count) { return New-ReadResult 'Absent' }
        Assert-CAclRecord $records[0]
        New-ReadResult 'Complete' $records
    } catch { if (Test-RunCancellation $_) { throw }; New-ReadResult 'Failed' @() @('AclOriginalRefused') }
}

function Clear-EventLog {
    param([string]$LogName)
    if (-not $LogName -or $LogName.Length -gt 512 -or $LogName -match '[\r\n\x00]') { throw 'Invalid event log name' }
    [Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($LogName)
}

function Set-CFileAttributes {
    param([string]$Path,[int]$Attributes)
    [IO.File]::SetAttributes($Path,[IO.FileAttributes]$Attributes)
}

function Get-CFileObservation {
    param([string]$Path)
    $canonical=Get-CanonicalFilePath $Path -MustExist
    $object=Get-RecoveryObject $canonical
    if ($object.Directory -or -not $object.Identity -or $object.Identity.Policy -ne 'VolumeFileId' -or -not $object.Identity.Value -or $object.Attributes -band 1024) { throw 'Only verified non-reparse NTFS files are supported; tree scope refused' }
    Assert-LocalVolume $canonical.Substring(0,2)
    @{ Identity=$object.Identity; Sddl=[string]$object.Acl.Sddl; Attributes=[int]$object.Attributes }
}

function Clear-CPSReadLineMemory { [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory() }

function Start-DeferredScriptRemoval {
    param([string]$ScriptPath)
    if($DryRun){return $false}
    $identity=$script:DeploymentIdentity
    if(-not $identity -or $ScriptPath -cne $identity.Path){throw 'No captured deployed-file identity'}
    Assert-TrustedPath $ScriptPath
    if(-not(Test-DataEqual (Get-RecoveryObject $ScriptPath).Identity $identity.Identity) -or (Get-NativeFileDigest $ScriptPath) -ine $identity.Digest){throw 'Deployed file changed'}
    $engine=Get-TrustedNativePath 'powershell.exe';Assert-NativeApproval $engine
    $path64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ScriptPath))
    $fileId=[string]$identity.Identity.Value;$digest=[string]$identity.Digest
    if($fileId -notmatch '^[a-fA-F0-9]{8}:[a-fA-F0-9]{16}$' -or $digest -notmatch '^[a-fA-F0-9]{64}$'){throw 'Unsupported deployed identity'}
    $body=@'
$ErrorActionPreference='Stop'
$path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PATH64__'))
$expected='__FILEID__';$digest='__DIGEST__'
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
public static class ExactFileRemoval {
 [StructLayout(LayoutKind.Sequential)] struct Info {public uint Attr;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string p,uint access,uint share,IntPtr sa,uint mode,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info info);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle h,int kind,ref byte disposition,uint length);
 public static bool Delete(string p,string expected,string digest) {
  using(var h=CreateFile(p,0x80010000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero)) {
   if(h.IsInvalid) return false;
   Info i;if(!GetFileInformationByHandle(h,out i)) return false;
   if((i.Attr & (1024|16))!=0 || i.Links!=1) throw new InvalidOperationException("Unsupported file");
   string id=i.Volume.ToString("x8")+":"+i.IndexHigh.ToString("x8")+i.IndexLow.ToString("x8");
   if(!String.Equals(id,expected,StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Replacement refused");
   using(var stream=new FileStream(h,FileAccess.Read)) using(var sha=SHA256.Create()) {
    if(stream.Length>16777216) throw new InvalidOperationException("File bound");
    var hash=BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","");
    if(!String.Equals(hash,digest,StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Changed file refused");
    byte remove=1;if(!SetFileInformationByHandle(h,4,ref remove,1)) return false;
    return true;
   }
  }
 }
}
"@
for($attempt=0;$attempt -lt 6;$attempt++) {Start-Sleep -Seconds 2;try{if([ExactFileRemoval]::Delete($path,$expected,$digest)){exit 0}}catch{exit 2}}
exit 1
'@
    $body=$body.Replace('__PATH64__',$path64).Replace('__FILEID__',$fileId).Replace('__DIGEST__',$digest)
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    Start-DeferredRemovalLeaf $engine $encoded
    return $true
}

function Remove-CHistoryFile {
    param([string]$Path)
    $canonical=Get-CanonicalFilePath $Path
    if (Test-Path -LiteralPath $canonical) {
        $object=Get-RecoveryObject $canonical
        if ($object.Directory) { throw 'History path is a directory' }
        Remove-Item -LiteralPath $canonical -Force -ErrorAction Stop
    }
}



function Assert-BoundedRecoveryArtifact {
    param([hashtable]$Artifact,[long]$Maximum)
    if (-not $Artifact.Complete -or $Maximum -lt 1) { throw 'Incomplete recovery artifact' }
    $path=Get-CanonicalFilePath $Artifact.CanonicalPath -MustExist
    if (-not (Test-PathWithin $path $OutDir)) { throw 'Artifact outside recovery storage' }
    Assert-TrustedPath $path -Confidential
    $object=Get-RecoveryObject $path
    if ($object.Directory -or $object.Length -le 0 -or $object.Length -gt $Maximum -or (Get-NativeFileDigest $path) -ine $Artifact.Digest) { throw 'Empty, oversized or changed artifact' }
}

function New-CFileLockDescriptor {
    param([string]$Sddl)
    $acl=New-Object Security.AccessControl.FileSecurity
    $acl.SetSecurityDescriptorSddlForm($Sddl)
    $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-1-0')), [Security.AccessControl.FileSystemRights]0x10116, 'Deny')
    $acl.AddAccessRule($rule)
    $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
}

function Copy-CRecoveryRecord {
    param([hashtable]$Record)
    # B owns data normalization; clone to avoid changing in-memory read fixtures
    # or an original record before successful durable publication.
    ConvertTo-RecoveryData (ConvertFrom-Json (ConvertTo-Json -InputObject $Record -Depth 20 -Compress))
}

function New-CRecoveryRecord {
    param([string]$Kind,[string]$Path,[hashtable]$Identity,$Prior,$Intended)
    if (-not $script:RecoveryContext -or -not $script:RecoveryContext.Handle) { throw 'Held recovery session required' }
    @{ SchemaVersion=1; RecordId=[guid]::NewGuid().ToString('D'); Revision=1; RunId=$script:State.RunId; MachineId=$script:RecoveryContext.MachineId; Kind=$Kind; ResourceId=$Path.ToUpperInvariant(); ResourceIdentity=$Identity; CanonicalPath=$Path; Ownership='Preexisting'; State='Intent'; Prior=$Prior; IntendedState=$Intended; AppliedObservation=$null; Artifact=@{ CanonicalPath=''; Digest=''; Complete=$false }; ChangedByRun=$false; Limits=@('Supported exact NTFS file object only; no uncaptured resource restoration') }
}

function Save-AclRecoveryRecord {
    param([string]$Target)
    if ($DryRun) { return New-ReadResult 'NotScanned' }
    try {
        Lock-AdminOnlyAcl $OutDir
        $read=Get-AclRecoveryRecord $Target
        if ($read.Status -eq 'Complete') { return $read }
        if ($read.Status -ne 'Absent') { throw 'Original not usable' }
        $canonical=Get-CanonicalFilePath $Target -MustExist
        $prior=Get-CFileObservation $canonical
        $intended=@{ Identity=$prior.Identity; Sddl=New-CFileLockDescriptor $prior.Sddl; Attributes=($prior.Attributes -bor 1) }
        $record=New-CRecoveryRecord 'Acl' $canonical $prior.Identity $prior $intended
        # The protected record contains the complete supported descriptor and
        # original attributes. No incomplete icacls artifact is consumed.
        Write-RecoveryRecord $record
        Get-AclRecoveryRecord $canonical
    } catch { if (Test-RunCancellation $_) { throw }; New-ReadResult 'Failed' @() @('AclSaveFailed') }
}

function Set-CFileDescriptor {
    param([string]$Path,[string]$Sddl)
    $acl=New-Object Security.AccessControl.FileSecurity
    $acl.SetSecurityDescriptorSddlForm($Sddl)
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Get-AccountSnapshot {
    $users = @(); $principals = @(); $errors = @(); $token = $null
    try {
        if ($State.IsDC -isnot [bool]) { throw 'Machine role unavailable' }
        if ($State.IsDC) { throw 'Local accounts unsupported on DC' }
        $users = @(Get-LocalUser -ErrorAction Stop)
        $seenSids = @{}; $seenNames = @{}
        foreach ($u in $users) {
            $sid = [string]$u.SID; $name = [string]$u.Name
            if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or [string]::IsNullOrWhiteSpace($name) -or $u.Enabled -isnot [bool] -or $seenSids.ContainsKey($sid) -or $seenNames.ContainsKey($name)) { throw 'Invalid local user observation' }
            $seenSids[$sid] = $true; $seenNames[$name] = $true
        }
    } catch [Management.Automation.PipelineStoppedException] { throw }
    catch { if (Test-RunCancellation $_) { throw }; $errors += 'Local user/role discovery failed'; $users = @() }
    try {
        $token = Get-AccountTokenSid
        if (@($token).Count -ne 1 -or [string]$token -notmatch '^S-1-\d+(-\d+)+$') { throw 'Token SID unavailable' }
    } catch [Management.Automation.PipelineStoppedException] { throw }
    catch { if (Test-RunCancellation $_) { throw }; $errors += 'Token discovery failed' }
    try {
        foreach ($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
            if ([string]::IsNullOrWhiteSpace([string]$service.StartName)) { throw 'Missing service principal' }
            $principals += [string]$service.StartName
        }
    } catch [Management.Automation.PipelineStoppedException] { throw }
    catch { if (Test-RunCancellation $_) { throw }; $errors += 'Service discovery failed' }
    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
            if ($task.Principal.UserId) { $principals += [string]$task.Principal.UserId }
            elseif ($task.Principal.GroupId) {
                foreach($member in @(Get-LocalGroupMember -Group $task.Principal.GroupId -ErrorAction Stop)){
                    if($member.ObjectClass -ne 'User'){throw 'Nested task group dependency requires manual account handling'}
                    $principals += [string]$member.SID; $principals += [string]$member.Name
                }
            } else { throw 'Missing task principal' }
        }
    } catch [Management.Automation.PipelineStoppedException] { throw }
    catch { if (Test-RunCancellation $_) { throw }; $errors += 'Task discovery failed' }
    $iis = @(Get-AccountIisPrincipals)
    if ($iis.Count -ne 1 -or $iis[0].Status -notin 'Complete','Absent') { $errors += 'IIS discovery incomplete' }
    else { $principals += @($iis[0].Items) }
    $principals += @($ExcludeUsers)
    $rows = @(foreach ($u in $users) {
        $sid = [string]$u.SID; $reasons = @()
        if ($sid -eq $token) { $reasons += 'CurrentToken' }
        foreach ($principal in $principals) {
            if ([string]::IsNullOrWhiteSpace([string]$principal)) { continue }
            if ([string]$principal -eq $sid -or ([string]$principal -replace '^.*\\') -eq $u.Name) { $reasons += 'DependencyOrExclusion' }
        }
        [pscustomobject]@{ SID=$sid; Name=[string]$u.Name; Enabled=[bool]$u.Enabled; Protected=($reasons.Count -gt 0); ProtectionReasons=[object[]]$reasons }
    })
    $status = if ($errors.Count) { if ($rows.Count) { 'Partial' } else { 'Failed' } } else { 'Complete' }
    New-ReadResult -Status $status -Items $rows -Errors $errors
}

function Test-AccountSecretEqual {
    param([Security.SecureString]$Left, [Security.SecureString]$Right)
    $a = $b = [IntPtr]::Zero
    try {
        if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) { return $false }
        $a = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Left)
        $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Right)
        for ($i = 0; $i -lt $Left.Length; $i++) {
            if ([Runtime.InteropServices.Marshal]::ReadInt16($a, 2*$i) -ne [Runtime.InteropServices.Marshal]::ReadInt16($b, 2*$i)) { return $false }
        }
        return $true
    } finally {
        if ($a -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($a) }
        if ($b -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
    }
}

function Get-AccountIisPrincipals {
    try {
        $feature = @(Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -ErrorAction Stop)
        if ($feature.Count -ne 1) { throw 'IIS applicability unavailable' }
        if ([string]$feature[0].State -in 'Disabled','DisabledWithPayloadRemoved') { return (New-ReadResult -Status Absent) }
        if ([string]$feature[0].State -ne 'Enabled') { throw 'IIS applicability uncertain' }
        $native = Invoke-NativeCommand -ExecutablePath (Get-TrustedNativePath -Name 'appcmd.exe') -Arguments @('list','apppool','/text:processModel.userName')
        New-ReadResult -Status Complete -Items @($native.Output | ForEach-Object { [string]$_ })
    } catch [Management.Automation.PipelineStoppedException] { throw }
    catch { if (Test-RunCancellation $_) { throw }; New-ReadResult -Status Failed -Errors @('IIS discovery failed') }
}

function Get-AccountTokenSid {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { $identity.User.Value } finally { $identity.Dispose() }
}

function Test-AccountMutationAllowed {
    param([string]$SID, [string]$ApprovedName, [ValidateSet('Delete','Password')][string]$Operation)
    $read = @(Get-AccountSnapshot)
    if ($read.Count -ne 1 -or $read[0].Status -ne 'Complete') { return (New-ReadResult -Status Failed -Errors @('Account authorization incomplete')) }
    $users = @($read[0].Items | Where-Object { $_.SID -eq $SID })
    $allowed = $false; $reason = 'Approved identity missing or changed'; $user = $null
    if ($users.Count -eq 1) {
        $user = $users[0]
        if ($user.Name -ceq $ApprovedName -and -not $user.Protected) {
            if ($Operation -eq 'Password') { $allowed = $user.Enabled }
            else { $allowed = ([long]($SID -split '-')[-1] -ge 1000) }
            $reason = if ($allowed) { 'Eligible' } else { 'Account ineligible' }
        }
    }
    New-ReadResult -Status Complete -Items @([pscustomobject]@{ Allowed=[bool]$allowed; Reason=$reason; User=$user })
}

function Test-ApprovedAccountSet {
    param([object[]]$Approved, [string]$Operation)
    foreach ($u in $Approved) {
        $permission = @(Test-AccountMutationAllowed -SID $u.SID -ApprovedName $u.Name -Operation $Operation)
        if ($permission.Count -eq 1 -and $permission[0].Status -eq 'Complete' -and @($permission[0].Items).Count -eq 1 -and $permission[0].Items[0].Allowed -is [bool] -and $permission[0].Items[0].Allowed -eq $true -and $permission[0].Items[0].User.SID -eq $u.SID -and $permission[0].Items[0].User.Name -ceq $u.Name -and (-not $u.Enabled -or $permission[0].Items[0].User.Enabled)) { $u }
        else { Add-RunFailure -Stage Accounts -Operation $Operation -Detail 'Approved account no longer authorized' }
    }
}

function Get-DodGpoSelection {
    param([string]$Root, [object[]]$Selection)
    if (-not $Root -or -not $Selection.Count -or $Selection.Count -gt 32) { throw 'GPO requires 1-32 explicitly approved ordered folders' }
    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if ($rootItem -isnot [IO.DirectoryInfo]) { throw 'GPO root must be a directory' }
    $rootPath = $rootItem.FullName.TrimEnd([IO.Path]::DirectorySeparatorChar)
    # Check all existing ancestors as well as descendants. Reparse traversal is refused.
    for ($ancestor = $rootItem; $null -ne $ancestor; $ancestor = $ancestor.Parent) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'GPO reparse ancestor refused' }
    }
    $seen = @{}; $results = @()
    foreach ($choice in $Selection) {
        if ($choice -isnot [hashtable] -or $choice.Approved -isnot [bool] -or -not $choice.Approved -or
            $choice.Files -isnot [hashtable] -or $choice.Files.Count -lt 2 -or $choice.Files.Count -gt 512) { throw 'Invalid GPO approval/manifest' }
        foreach ($field in 'Folder','Package','Version','Role') {
            if ($choice[$field] -isnot [string] -or [string]::IsNullOrWhiteSpace($choice[$field]) -or $choice[$field].Length -gt 256) { throw 'GPO approval needs concrete folder/package/version/role' }
        }
        if ($choice.Folder -in '.', '..' -or $choice.Folder -match '[\\/:]' -or $seen.ContainsKey($choice.Folder)) { throw 'Ambiguous GPO folder selection' }
        $seen[$choice.Folder] = $true
        $folder = Get-Item -LiteralPath (Join-Path $rootPath $choice.Folder) -Force -ErrorAction Stop
        if ($folder -isnot [IO.DirectoryInfo] -or $folder.Parent.FullName.TrimEnd([IO.Path]::DirectorySeparatorChar) -ine $rootPath) { throw 'GPO selection must be a direct child directory' }
        $prefix = $folder.FullName + [IO.Path]::DirectorySeparatorChar
        $pending = @($folder); $files = @{}; $nodes = 0; $bytes = 0L; $payload = $false
        while ($pending.Count) {
            $directory = $pending[0]; $pending = @($pending | Select-Object -Skip 1)
            if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'GPO reparse directory refused' }
            foreach ($entry in @(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction Stop)) {
                $nodes++; if ($nodes -gt 1024) { throw 'GPO tree exceeds entry bound' }
                if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'GPO reparse entry refused' }
                if (-not $entry.FullName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'GPO path escaped selection' }
                $relative = $entry.FullName.Substring($prefix.Length).Replace('\','/')
                if ($relative.Split('/').Count -gt 16 -or $relative.Length -gt 240) { throw 'GPO tree exceeds path bound' }
                if ($entry -is [IO.DirectoryInfo]) { $pending += $entry; continue }
                if ($entry -isnot [IO.FileInfo]) { throw 'GPO entry is not a regular file' }
                $bytes += $entry.Length
                if ($entry.Length -gt 16MB -or $bytes -gt 64MB) { throw 'GPO payload exceeds byte bound' }
                if (-not $choice.Files.ContainsKey($relative) -or $choice.Files[$relative] -isnot [string] -or $choice.Files[$relative] -notmatch '^[a-fA-F0-9]{64}$') { throw 'Unapproved GPO payload' }
                if ((Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256 -ErrorAction Stop).Hash -ine $choice.Files[$relative]) { throw 'GPO payload digest changed' }
                if ($entry.Extension -ieq '.xml') {
                    $settings = New-Object Xml.XmlReaderSettings
                    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit; $settings.XmlResolver = $null
                    $settings.MaxCharactersInDocument = 16MB
                    $reader = [Xml.XmlReader]::Create($entry.FullName, $settings)
                    try {
                        $document = New-Object Xml.XmlDocument; $document.XmlResolver = $null; $document.Load($reader)
                        if ($relative -ieq 'Backup.xml' -and $document.DocumentElement.LocalName -ne 'GroupPolicyBackupScheme') { throw 'Invalid Backup.xml wrapper' }
                    } finally { $reader.Dispose() }
                }
                if ($relative -match '^DomainSysvol/GPO/(Machine|User)/.+') {
                    if (-not $entry.Length) { throw 'Empty GPO policy payload' }
                    $payload = $true
                }
                $files[$relative] = $true
            }
        }
        if (-not $files.ContainsKey('Backup.xml') -or -not $payload -or $files.Count -ne $choice.Files.Count) { throw 'Incomplete GPO backup/manifest' }
        $results += [pscustomobject]@{ Path=$folder.FullName; Package=$choice.Package; Version=$choice.Version; Role=$choice.Role; Approval=$choice }
    }
    # All selections validate before any import. Order is exactly the operator array.
    $results
}
function Get-FirewallSnapshot {
    try {
        $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        if ($profiles.Count -ne 3 -or @($profiles.Name | Select-Object -Unique).Count -ne 3) { throw 'Profile observation incomplete' }
        foreach ($profile in $profiles) {
            if ($profile.Name -notin 'Domain','Private','Public' -or [string]$profile.Enabled -notin 'True','False' -or [string]$profile.DefaultInboundAction -notin 'Allow','Block' -or [string]$profile.AllowLocalFirewallRules -notin 'True','False','NotConfigured') { throw 'Unknown effective profile' }
        }
        $rules=@(foreach ($rule in @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)) {
            $port=@($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
            $address=@($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
            $app=@($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
            $service=@($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
            $interface=@($rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
            $security=@($rule | Get-NetFirewallSecurityFilter -ErrorAction Stop)
            if ($port.Count -ne 1 -or $address.Count -ne 1 -or $app.Count -ne 1 -or $service.Count -ne 1 -or $interface.Count -ne 1 -or $security.Count -ne 1) { throw 'Rule filters incomplete' }
            [pscustomobject]@{Name=$rule.Name;Direction=[string]$rule.Direction;Action=[string]$rule.Action;Enabled=[string]$rule.Enabled;Profile=[string]$rule.Profile;Source=[string]$rule.PolicyStoreSourceType;Rule=$rule;Port=$port[0];Address=$address[0];Application=$app[0];Service=$service[0];Interface=$interface[0];Security=$security[0]}
        })
        New-ReadResult 'Complete' @([pscustomobject]@{Profiles=[object[]]$profiles;Rules=[object[]]$rules})
    } catch { if (Test-RunCancellation $_) { throw }; New-ReadResult 'Failed' @() @('EffectiveFirewallObservationFailed') }
}

function Test-FirewallPortMatch {
    param($Ports,[int]$Port)
    foreach ($entry in @($Ports)) {
        if ([string]$entry -eq 'Any') { return $true }
        if ([string]$entry -match '^\d+$' -and [int]$entry -eq $Port) { return $true }
        if ([string]$entry -match '^(\d+)-(\d+)$' -and $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
    }
    return $false
}

function Test-ControlRule {
    param($Rule,[string]$Proto,[int]$Port,[string]$Action='Allow',[int]$RemotePort=0,[string]$Service='Any')
    $protocol=if($Proto -eq 'TCP'){@('TCP','6')}else{@('UDP','17')}
    [bool]($Rule.Direction -eq 'Inbound' -and $Rule.Action -eq $Action -and $Rule.Enabled -eq 'True' -and $Rule.Profile -eq 'Any' -and
        [string]$Rule.Port.Protocol -in $protocol -and @($Rule.Port.LocalPort).Count -eq 1 -and [string]$Rule.Port.LocalPort -eq [string]$Port -and
        @($Rule.Port.RemotePort).Count -eq 1 -and [string]$Rule.Port.RemotePort -eq $(if($RemotePort){[string]$RemotePort}else{'Any'}) -and
        [string]$Rule.Address.LocalAddress -eq 'Any' -and [string]$Rule.Address.RemoteAddress -eq 'Any' -and
        [string]$Rule.Application.Program -eq 'Any' -and [string]$Rule.Application.Package -eq 'Any' -and [string]$Rule.Service.Service -eq $Service -and
        [string]$Rule.Interface.InterfaceAlias -eq 'Any' -and [string]$Rule.Security.Authentication -eq 'NotRequired' -and [string]$Rule.Security.Encryption -eq 'NotRequired')
}

function Assert-EffectiveControl {
    param([string]$Name,[string]$Proto,[int]$Port,[string]$Action='Allow',[int]$RemotePort=0,[string]$Service='Any')
    $read=Get-FirewallSnapshot
    if ($read.Status -ne 'Complete' -or $read.Items.Count -ne 1) { throw 'Effective firewall unknown' }
    $snapshot=$read.Items[0]
    if (@($snapshot.Profiles | Where-Object { [string]$_.AllowLocalFirewallRules -eq 'False' }).Count) { throw 'Local firewall policy merge disabled' }
    $rules=@($snapshot.Rules | Where-Object Name -eq $Name)
    if ($rules.Count -ne 1 -or -not (Test-ControlRule $rules[0] $Proto $Port $Action $RemotePort $Service)) { throw 'Control absent or invalid in effective policy' }
    if ($Action -eq 'Allow') {
        foreach ($rule in $snapshot.Rules) {
            if ($rule.Enabled -eq 'True' -and $rule.Direction -eq 'Inbound' -and $rule.Action -eq 'Block' -and [string]$rule.Port.Protocol -in @($Proto,$(if($Proto -eq 'TCP'){'6'}else{'17'}),'Any','256') -and (Test-FirewallPortMatch $rule.Port.LocalPort $Port)) { throw 'Effective blocking rule conflicts with control' }
        }
    }
}

function Add-DhcpControl {
    param([int]$LocalPort,[int]$RemotePort)
    $name="HPCC4-DHCP-$LocalPort"
    Invoke-Step $name {
        $existing=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Name -eq $name)
        if ($existing.Count -gt 1) { throw 'Duplicate DHCP control' }
        if (-not $existing.Count) { $null=New-NetFirewallRule -Name $name -DisplayName $name -Direction Inbound -Protocol UDP -LocalPort $LocalPort -RemotePort $RemotePort -Service Dhcp -Action Allow -Profile Any -PolicyStore PersistentStore -ErrorAction Stop }
        Assert-EffectiveControl $name 'UDP' $LocalPort 'Allow' $RemotePort 'Dhcp'
    }
}

function Test-FirewallBackupReady {
    $read=Read-RecoveryRecords $OutDir 'Firewall'
    if ($read.Status -ne 'Complete') { return $false }
    $records=@($read.Items | Where-Object { $_.State -eq 'Applied' -and $_.Artifact.Complete })
    if ($records.Count -ne 1) { return $false }
    try { Assert-BoundedRecoveryArtifact $records[0].Artifact 16777216; return $true }
    catch { if(Test-RunCancellation $_){throw};return $false }
}

function Get-PostGpoPolicyObservation {
    $read=Get-FirewallSnapshot
    try {$port=Get-RuntimeRdpPort;if([string]$port -notmatch '^\d+$' -or $port -lt 1 -or $port -gt 65535){throw 'Invalid RDP observation'}}
    catch{if(Test-RunCancellation $_){throw};return New-ReadResult 'Failed' @() @('RdpObservationFailed')}
    if($read.Status -ne 'Complete'){return $read}
    New-ReadResult 'Complete' @([pscustomobject]@{Source='ActiveStore plus RDP control registry';Firewall=$read.Items[0];RdpPort=[int]$port})
}
function Save-ContentOriginal {
    param([string]$Path)
    $canonical=Get-CanonicalFilePath $Path -MustExist
    $object=Get-RecoveryObject $canonical
    $files=@($canonical)
    if($object.Directory){
        # Walk one level at a time; do not traverse junctions before inspecting them.
        $files=@();$queue=New-Object 'Collections.Generic.Queue[string]';$queue.Enqueue($canonical);$count=0
        while($queue.Count){foreach($item in @(Get-ChildItem -LiteralPath $queue.Dequeue() -Force -ErrorAction Stop)){
            $count++;if($count -gt 1024 -or $item.Attributes -band 1024){throw 'Content tree limit/reparse refused'}
            if($item.PSIsContainer){$queue.Enqueue($item.FullName)}else{$files+=$item.FullName}
        }}
    }
    foreach($file in $files){
        $file=Get-CanonicalFilePath $file -MustExist;$current=Get-RecoveryObject $file
        if($current.Directory -or $current.Length -gt 67108864){throw 'Content file exceeds supported bound'}
        $read=Read-RecoveryRecords $OutDir 'Artifact';if($read.Status -notin 'Complete','Absent'){throw 'Content metadata unhealthy'}
        $old=@($read.Items | Where-Object {$_.ResourceId -eq $file.ToUpperInvariant() -and $_.State -ne 'Restored'})
        if($old.Count){if($old.Count -ne 1 -or $old[0].State -ne 'Applied'){throw 'Incomplete original retained'};Assert-BoundedRecoveryArtifact $old[0].Artifact 67108864;continue}
        $digest=Get-NativeFileDigest $file
        $backup=Join-Path $OutDir ('content-'+[guid]::NewGuid().ToString('N')+'.bin')
        Copy-ProtectedInput $file $backup
        $artifact=@{CanonicalPath=$backup;Digest=Get-NativeFileDigest $backup;Complete=$true}
        if($artifact.Digest -ine $digest -or (Get-NativeFileDigest $file) -ine $digest -or -not(Test-DataEqual (Get-RecoveryObject $file).Identity $current.Identity)){throw 'Original changed while copied; orphan retained'}
        $prior=@{Identity=$current.Identity;Sddl=$current.Acl.Sddl;Attributes=$current.Attributes;Digest=$digest}
        $record=New-CRecoveryRecord 'Artifact' $file $current.Identity $prior $null;$record.Artifact=$artifact
        Write-RecoveryRecord $record;$record=Copy-CRecoveryRecord $record;$record.Revision++;$record.State='Applied';$record.AppliedObservation=@{SavedArtifact=$artifact}
        Write-RecoveryRecord $record
    }
}

function Copy-ProtectedInput {
    param([string]$Source,[string]$Destination)
    $source=Get-CanonicalFilePath $Source -MustExist;$destination=Get-CanonicalFilePath $Destination
    Assert-TrustedPath ([IO.Path]::GetDirectoryName($destination)) -NoChildCreate -Confidential
    $input=$null;$output=$null;$primary=$null
    try{
        $input=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if($input.Length -gt 268435456){throw 'Input exceeds 256 MiB'}
        $output=Open-ProtectedRecoveryFile $destination;$input.CopyTo($output);$output.Flush($true)
    }catch{$primary=$_;if(Test-RunCancellation $_){$State.Cancelled=$true};throw}
    finally{
        foreach($stream in @($output,$input)){if($null -ne $stream){try{$stream.Dispose()}catch{Add-RunFailure 'Storage' 'CloseCopy' $_.Exception.GetType().Name;if($primary){throw $primary};throw}}}
    }
    Assert-TrustedPath $destination -Confidential
}

function Expand-ProtectedArchive {
    param([string]$Zip,[string]$Destination)
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    Assert-TrustedPath $Zip -Confidential;Assert-TrustedPath $Destination -NoChildCreate -Confidential
    $archive=[IO.Compression.ZipFile]::OpenRead($Zip)
    try{
        if($archive.Entries.Count -gt 1024){throw 'Archive entry limit'}
        $total=0L;$seen=@{}
        foreach($entry in $archive.Entries){
            $relative=$entry.FullName.Replace('/','\').TrimEnd('\')
            if(-not $relative -or $relative -match '(^\\|:|(^|\\)\.\.?($|\\)|[\x00-\x1f])' -or $relative.Split('\').Count -gt 16){throw 'Unsafe archive member'}
            $target=Get-CanonicalFilePath (Join-Path $Destination $relative)
            if(-not(Test-PathWithin $target $Destination) -or $seen.ContainsKey($target)){throw 'Duplicate/escaping archive member'}
            $seen[$target]=$true;$total+=$entry.Length
            if($entry.Length -gt 67108864 -or $total -gt 268435456){throw 'Archive size bound'}
        }
        foreach($entry in $archive.Entries){
            $target=Get-CanonicalFilePath (Join-Path $Destination $entry.FullName.Replace('/','\').TrimEnd('\'))
            $parent=[IO.Path]::GetDirectoryName($target)
            $missing=@();while(-not(Test-Path -LiteralPath $parent)){$missing+=,$parent;$parent=[IO.Path]::GetDirectoryName($parent)}
            for($i=$missing.Count-1;$i -ge 0;$i--){Initialize-ProtectedDirectory $missing[$i]}
            if(-not $entry.Name){Initialize-ProtectedDirectory $target;continue}
            $stream=$entry.Open();$output=$null
            try{$output=Open-ProtectedRecoveryFile $target;$stream.CopyTo($output);$output.Flush($true)}finally{if($output){$output.Dispose()};$stream.Dispose()}
            if((Get-Item -LiteralPath $target -Force -ErrorAction Stop).Length -ne $entry.Length){throw 'Extraction incomplete'}
            Assert-TrustedPath $target -Confidential
        }
    }finally{$archive.Dispose()}
}

function Approve-RoleExecutable {
    param([string]$Path,[string]$Role,[switch]$Pinned)
    $path=Get-CanonicalFilePath $Path -MustExist
    $policy=if($Pinned){'PinnedDigest'}elseif($Role -eq 'AV' -and $AvInstallerExpectedSigner){'ExpectedSigner'}else{'ValidSignature'}
    Register-NativeApproval $path $Role (Get-NativeFileDigest $path) $policy (Get-RecoveryObject $path).Identity
    return $path
}

function Install-AcceptedSysmon {
    param([string]$Package,[switch]$Pinned)
    $State.ToolReadiness.Sysmon='Failed'
    $exe=Approve-RoleExecutable (Join-Path $Package 'Sysmon64.exe') 'Sysmon' -Pinned:$Pinned
    $cfg=Get-CanonicalFilePath (Join-Path $Package 'sysmonconfig.xml') -MustExist
    Assert-TrustedPath $cfg -Confidential;$cfgIdentity=(Get-RecoveryObject $cfg).Identity;$cfgDigest=Get-NativeFileDigest $cfg
    $services=@(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object {$_.Name -in 'Sysmon','Sysmon64'})
    $record=New-CRecoveryRecord 'Tool' $exe (Get-RecoveryObject $exe).Identity @{PreexistingService=($services.Count -gt 0);ConfigRestorable=$false} $null
    $record.Ownership=if($services.Count){'Preexisting'}else{'Created'};Write-RecoveryRecord $record
    # Preexisting configuration is not captured by Sysmon: do not imply rollback.
    if(Invoke-Step 'install/update accepted Sysmon configuration' {
        if(-not(Test-DataEqual (Get-RecoveryObject $cfg).Identity $cfgIdentity) -or (Get-NativeFileDigest $cfg) -ine $cfgDigest){throw 'Sysmon config changed'}
        $arguments=if($services.Count){@('-c',$cfg)}else{@('-accepteula','-i',$cfg)}
        $null=Invoke-NativeCommand $exe $arguments
        $after=@(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object {$_.Name -in 'Sysmon','Sysmon64'})
        if($after.Count -ne 1 -or $after[0].State -ne 'Running'){throw 'Sysmon health not observed'}
        $updated=Copy-CRecoveryRecord $record;$updated.Revision++;$updated.State='Applied';$updated.ChangedByRun=$true
        $updated.AppliedObservation=@{ServiceName=$after[0].Name;PathName=$after[0].PathName;StartName=$after[0].StartName;State=$after[0].State;StartMode=$after[0].StartMode}
        Write-RecoveryRecord $updated
    }){$State.ToolReadiness.Sysmon='Complete'}
}

function Get-RawRegistryValue {
    param([string]$Key,[string]$Name)
    if(-not(Test-Path -LiteralPath $Key)){return @{KeyExists=$false;Exists=$false;Kind='None';Value=$null}}
    $item=Get-Item -LiteralPath $Key -ErrorAction Stop
    try{
        $exists=@($item.GetValueNames()) -contains $Name
        if($exists){
            $kind=$item.GetValueKind($Name).ToString()
            $value=$item.GetValue($Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            # Journal primitives must preserve raw bytes and every multi-string
            # member across JSON; restore reconstructs the registry CLR types.
            if($value -is [byte[]]){$value=[int[]]$value}
            return @{KeyExists=$true;Exists=$true;Kind=$kind;Value=$value}
        }
        return @{KeyExists=$true;Exists=$false;Kind='None';Value=$null}
    }finally{$item.Dispose()}
}

function Set-RawRegistryValue {
    param([string]$Key,[string]$Name,[hashtable]$Observation)
    if(-not $Observation.Exists){if(Test-Path -LiteralPath $Key){Remove-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction Stop};return}
    if(-not(Test-Path -LiteralPath $Key)){$null=New-Item -Path $Key -Force -ErrorAction Stop}
    $item=Get-Item -LiteralPath $Key -ErrorAction Stop
    try{
        $value=$Observation.Value
        switch($Observation.Kind){
            Binary {$value=[byte[]]$value}
            Unknown {$value=[byte[]]$value}
            MultiString {$value=[string[]]$value}
            DWord {$value=[int]$value}
            QWord {$value=[long]$value}
        }
        $item.SetValue($Name,$value,[Microsoft.Win32.RegistryValueKind]$Observation.Kind)
    }finally{$item.Dispose()}
}

function Set-OwnedRegistryValue {
    param([string]$Key,[string]$Name,[string]$Kind,$Value)
    $read=Read-RecoveryRecords $OutDir 'Registry';if($read.Status -notin 'Complete','Absent'){throw 'Registry originals unreadable'}
    $resource=$Key+'|'+$Name;$old=@($read.Items | Where-Object {$_.ResourceId -eq $resource -and $_.State -ne 'Restored'})
    $prior=Get-RawRegistryValue $Key $Name
    if($old.Count){if($old.Count -ne 1 -or $old[0].State -ne 'Applied' -or -not(Test-DataEqual $prior $old[0].AppliedObservation)){throw 'Registry conflict; original retained'};return}
    $next=Copy-CRecoveryRecord $prior
    if($Kind -eq 'AppendPath'){
        if($prior.Exists -and $prior.Kind -notin 'String','ExpandString'){throw 'Unsupported PATH kind'}
        if(@([string]$prior.Value -split ';' | ForEach-Object {$_.TrimEnd('\')}) -contains ([string]$Value).TrimEnd('\')){return}
        $next.Kind=if($prior.Exists){$prior.Kind}else{'ExpandString'};$next.Value=if([string]$prior.Value){[string]$prior.Value+';'+$Value}else{[string]$Value}
    }else{$next.Kind=$Kind;$next.Value=$Value}
    $next.Exists=$true;$next.KeyExists=$true
    if(Test-DataEqual $prior $next){return}
    $record=New-CRecoveryRecord 'Registry' $OutDir $null $prior $next;$record.ResourceId=$resource
    $record.ResourceIdentity=@{Policy='RegistryValue';Key=$Key;Name=$Name};Write-RecoveryRecord $record
    if(Invoke-Step "publish registry value $Name" {
        if(-not(Test-DataEqual (Get-RawRegistryValue $Key $Name) $prior)){throw 'Registry changed before write'}
        Set-RawRegistryValue $Key $Name $next
        $after=Get-RawRegistryValue $Key $Name;if(-not(Test-DataEqual $after $next)){throw 'Registry write not observed'}
        $done=Copy-CRecoveryRecord $record;$done.Revision++;$done.State='Applied';$done.AppliedObservation=$after;$done.ChangedByRun=$true;Write-RecoveryRecord $done
    }){Write-Log "$Name published; current-session PATH is unchanged."}
}

function Save-LocalPolicyRecoveryRecord {
    param([string]$LgpoPath)
    try{
        Lock-AdminOnlyAcl $OutDir
        $read=Read-RecoveryRecords $OutDir 'LocalPolicy';if($read.Status -notin 'Complete','Absent'){throw 'Local-policy metadata incomplete'}
        $active=@($read.Items | Where-Object State -ne 'Restored')
        if($active.Count){if($active.Count -ne 1 -or $active[0].State -ne 'Applied'){throw 'Incomplete local-policy original'};Assert-BoundedRecoveryArtifact $active[0].Artifact 1048576;Test-PolicyBackupManifest $active[0];return New-ReadResult 'Complete' $active}
        $folder=Join-Path $OutDir ('local-policy-'+[guid]::NewGuid().ToString('N'));Initialize-ProtectedDirectory $folder
        $null=Invoke-NativeCommand $LgpoPath @('/b',$folder)
        $entries=Get-ProtectedTreeManifest $folder
        if(-not @($entries | Where-Object {$_.Relative -like '*Backup.xml'}).Count -or -not @($entries | Where-Object {$_.Relative -like '*registry.pol' -or $_.Relative -like '*GptTmpl.inf'}).Count){throw 'Local backup payload incomplete'}
        $manifest=Join-Path $OutDir ('policy-manifest-'+[guid]::NewGuid().ToString('N')+'.json')
        Write-RecoveryBytes $manifest ([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @($entries) -Depth 6 -Compress)))
        $object=Get-RecoveryObject $folder;$record=New-CRecoveryRecord 'LocalPolicy' $folder $object.Identity @{BackupFolder=$folder} $null
        $record.Artifact=@{CanonicalPath=$manifest;Digest=Get-NativeFileDigest $manifest;Complete=$true};Write-RecoveryRecord $record
        $record=Copy-CRecoveryRecord $record;$record.Revision++;$record.State='Applied';$record.AppliedObservation=@{SavedManifest=$record.Artifact};Write-RecoveryRecord $record
        New-ReadResult 'Complete' @($record)
    }catch{if(Test-RunCancellation $_){throw};New-ReadResult 'Failed' @() @('LocalPolicyBackupFailed')}
}

function Get-ProtectedTreeManifest {
    param([string]$Root)
    Assert-TrustedPath $Root -NoChildCreate -Confidential
    $queue=New-Object 'Collections.Generic.Queue[string]';$queue.Enqueue($Root);$rows=@();$count=0;$total=0L
    while($queue.Count){foreach($item in @(Get-ChildItem -LiteralPath $queue.Dequeue() -Force -ErrorAction Stop)){
        $count++;if($count -gt 1024 -or $item.Attributes -band 1024){throw 'Protected tree limit/reparse'}
        Assert-TrustedPath $item.FullName -Confidential
        if($item.PSIsContainer){$queue.Enqueue($item.FullName)}else{
            $total+=$item.Length;if($item.Length -gt 16777216 -or $total -gt 67108864){throw 'Protected tree size bound'}
            $rows+=@{Relative=$item.FullName.Substring($Root.Length+1);Length=[long]$item.Length;Digest=Get-NativeFileDigest $item.FullName;Identity=(Get-RecoveryObject $item.FullName).Identity}
        }
    }}
    return @($rows | Sort-Object Relative)
}

function Test-PolicyBackupManifest {
    param([hashtable]$Record)
    if(-not(Test-DataEqual (Get-RecoveryObject $Record.CanonicalPath).Identity $Record.ResourceIdentity)){throw 'Local-policy backup folder changed'}
    $expected=ConvertTo-RecoveryData (ConvertFrom-Json -InputObject (Get-Content -LiteralPath $Record.Artifact.CanonicalPath -Raw -ErrorAction Stop) -ErrorAction Stop)
    $actual=@(Get-ProtectedTreeManifest $Record.CanonicalPath)
    if(-not(Test-DataEqual @($expected) $actual)){throw 'Local-policy backup bytes changed'}
}
function Read-PersistenceSource {
    param([string]$Name,[scriptblock]$Action)
    try{$items=@(& $Action);New-ReadResult 'Complete' $items}
    catch [Management.Automation.ItemNotFoundException]{New-ReadResult 'Absent'}
    catch [Management.Automation.DriveNotFoundException]{New-ReadResult 'Failed' @() @('ProviderUnavailable')}
    catch{if(Test-RunCancellation $_){throw};New-ReadResult 'Failed' @() @('SourceReadFailed')}
}

function New-PersistenceRows {
    param([string]$Type,[string]$Name,$Values)
    $index=0
    foreach($value in @($Values)){
        [pscustomobject]@{Type=$Type;Name=$Name;Member=$index;Command=[string]$value;Suspicious=[bool](Test-SuspiciousPath ([string]$value))}
        $index++
    }
}

function Get-PersistenceRegistryRows {
    param([string]$Key,[string]$Type,[string[]]$Values=@())
    $properties=(Get-ItemProperty -LiteralPath $Key -ErrorAction Stop).PSObject.Properties
    foreach($property in $properties){
        if($property.Name -notin $script:PsSyntheticProps -and (-not $Values.Count -or $property.Name -in $Values)){
            New-PersistenceRows $Type ($Key+'|'+$property.Name) $property.Value
        }
    }
}

function Get-StartupLinkTarget {
    param([string]$Path)
    $shell=$null;$link=$null
    try{$shell=New-Object -ComObject WScript.Shell;$link=$shell.CreateShortcut($Path);@($link.TargetPath,$link.Arguments,$link.WorkingDirectory)}
    finally{if($link){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($link)};if($shell){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}}
}

function Initialize-DeploymentIdentity {
    param([string]$Path)
    $script:DeploymentIdentity=$null
    if($DryRun -or $Unlock -or -not $Cleanup){return}
    $path=Get-CanonicalFilePath $Path -MustExist;Assert-TrustedPath $path
    $object=Get-RecoveryObject $path
    if($object.Directory -or [IO.Path]::GetExtension($path) -ine '.ps1'){throw 'Exact regular deployed PS1 required'}
    $script:DeploymentIdentity=@{Path=$path;Identity=$object.Identity;Digest=Get-NativeFileDigest $path}
}

function Start-DeferredRemovalLeaf {
    param([string]$Engine,[string]$EncodedCommand)
    $null=Start-Process -FilePath $Engine -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$EncodedCommand) -WindowStyle Hidden -ErrorAction Stop
}
function Restore-OwnedRegistryRecord {
    param([hashtable]$Record)
    if($DryRun){return $false}
    try{
        $identity=$Record.ResourceIdentity
        if($identity.Policy -ne 'RegistryValue' -or
            ($identity.Key -ne 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -or $identity.Name -ne 'Path') -and
            ($identity.Key -ne 'HKCU:\Software\Sysinternals' -or $identity.Name -ne 'EulaAccepted')){throw 'Unsupported recorded registry resource'}
        $read=Read-RecoveryRecords $OutDir 'Registry';$matches=@($read.Items | Where-Object RecordId -eq $Record.RecordId)
        if($read.Status -ne 'Complete' -or $matches.Count -ne 1 -or -not(Test-DataEqual $matches[0] $Record)){throw 'Stale registry original'}
        $current=Get-RawRegistryValue $identity.Key $identity.Name
        if($Record.State -eq 'Intent'){
            if(-not(Test-DataEqual $current $Record.Prior)){throw 'Unobserved registry write; manual recovery'}
        }elseif($Record.State -notin 'Applied','RestoreFailed' -or -not(Test-DataEqual $current $Record.AppliedObservation)){throw 'Later registry change; original retained'}
        if(-not(Test-DataEqual $current $Record.Prior)){
            if(-not(Test-DataEqual (Get-RawRegistryValue $identity.Key $identity.Name) $current)){throw 'Registry changed before restore'}
            Set-RawRegistryValue $identity.Key $identity.Name $Record.Prior
        }
        $after=Get-RawRegistryValue $identity.Key $identity.Name
        # A new key remains because deleting it could erase unrelated members.
        if(-not $Record.Prior.KeyExists){$after.KeyExists=$false}
        if(-not(Test-DataEqual $after $Record.Prior)){throw 'Original raw value not observed'}
        $done=Copy-CRecoveryRecord $Record;$done.Revision++;$done.State='Restored';$done.AppliedObservation=$after;Write-RecoveryRecord $done
        return $true
    }catch{if(Test-RunCancellation $_){throw};Add-RunFailure 'Registry' 'Restore' $_.Exception.GetType().Name;return $false}
}
function Initialize-OwnedToolDirectory {
    param([string]$Path)
    $path=Get-CanonicalFilePath $Path
    Lock-AdminOnlyAcl $OutDir
    $read=Read-RecoveryRecords $OutDir 'Tool';if($read.Status -notin 'Complete','Absent'){throw 'Tool originals unreadable'}
    $active=@($read.Items | Where-Object {$_.ResourceId -eq $path.ToUpperInvariant() -and $_.State -ne 'Restored'})
    if($active.Count){
        if($active.Count -ne 1 -or $active[0].State -ne 'Applied'){throw 'Interrupted tool directory; manual recovery'}
        $object=Get-RecoveryObject $path
        if(-not(Test-DataEqual $object.Identity $active[0].ResourceIdentity)){throw 'Tool directory replacement'}
        Assert-TrustedPath $path -NoChildCreate -Confidential;return
    }
    if(Test-Path -LiteralPath $path){Assert-TrustedPath $path -NoChildCreate -Confidential;return}
    Assert-TrustedPath ([IO.Path]::GetDirectoryName($path))
    $record=New-CRecoveryRecord 'Tool' $path $null @{Exists=$false} $null;$record.Ownership='Created'
    $record.Limits=@('Created staging directory; retain contents on reset, never adopt unobserved identity')
    Write-RecoveryRecord $record
    New-RecoveryDirectory $path
    Assert-TrustedPath $path -NoChildCreate -Confidential
    $object=Get-RecoveryObject $path
    if(-not $object.Directory -or @(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop).Count){throw 'New tool directory incomplete'}
    $record=Copy-CRecoveryRecord $record;$record.Revision++;$record.State='Applied';$record.ResourceIdentity=$object.Identity
    $record.AppliedObservation=@{Directory=$true;Identity=$object.Identity;Sddl=$object.Acl.Sddl;Attributes=$object.Attributes};$record.ChangedByRun=$true
    Write-RecoveryRecord $record
}

function Stage-DodGpoInputs {
    param([object[]]$Selected)
    Lock-AdminOnlyAcl $OutDir
    $root=Join-Path $OutDir ('gpo-input-'+$State.RunId);Initialize-ProtectedDirectory $root
    $State.GpoInputRoot=$root
    foreach($item in $Selected){
        $folder=Join-Path $root $item.Approval.Folder;Initialize-ProtectedDirectory $folder
        foreach($relative in $item.Approval.Files.Keys){
            $destination=Get-CanonicalFilePath (Join-Path $folder $relative)
            $parent=[IO.Path]::GetDirectoryName($destination);$missing=@()
            while(-not(Test-Path -LiteralPath $parent)){$missing+=,$parent;$parent=[IO.Path]::GetDirectoryName($parent)}
            for($index=$missing.Count-1;$index -ge 0;$index--){Initialize-ProtectedDirectory $missing[$index]}
            Copy-ProtectedInput (Join-Path $item.Path $relative) $destination
            if((Get-NativeFileDigest $destination) -ine $item.Approval.Files[$relative]){throw 'Selected GPO changed during staging'}
        }
    }
    Get-DodGpoSelection -Root $root -Selection @($Selected | ForEach-Object {$_.Approval})
}
if ($MyInvocation.InvocationName -ne '.') { Invoke-DirectEntry }
