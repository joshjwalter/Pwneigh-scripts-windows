# HPCC4 defensive helper: backup, firewall, unauthorized-account removal, local passwords, tools, ACL lock.
# Every change runs through Invoke-Step, so one failure never stops the rest. Windows PowerShell 5.1, Server 2022-2025.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', 'Write-Log', Justification = 'Defined in this script')]
param([switch]$DryRun, [switch]$Unlock, [switch]$Cleanup)
# ---- Tunables (nothing else in this script is hardcoded) ----
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
$AvInstallerUrl = 'https://free.360totalsecurity.com/totalsecurity/360TS_Setup_Mini.exe'   # downloaded to $ToolsDir; opens at the END for you to click through ('' = skip)
$InstallSysmon  = $false       # true = install/update Sysmon if Sysmon64.exe and sysmonconfig.xml are in the zip
$BackupPaths    = @('C:\Windows\System32\drivers\etc\hosts')
$LockPaths      = @('C:\Windows\System32\drivers\etc\hosts')
$OutDir         = 'C:\HPCC4'   # backups, firewall backup, saved ACLs for -Unlock (no logs: output goes to the terminal only)
$State = @{ IsDC = $false; RdpPort = 3389; BackupDir = ''; Uncovered = @(); Purge = $false; Enable = $true; FirewallOn = $false; RulesAdded = @(); BlocksRefused = @(); Deleted = @(); Changed = @(); ToolsInstalled = $false; HashChecked = 'no'; AvInstaller = ''; Locked = @(); Failures = @() }

# ---- Helpers ----
function Write-Log { param([string]$Message); Write-Host "$(Get-Date -Format 'HH:mm:ss') $Message" }   # terminal only; nothing is written to disk
# Runs one change. -DryRun: log WOULD and run nothing. Fails on an exception, a cmdlet error, or a native exit code
# (robocopy: 8+ fails, 0-7 is success; everything else: non-zero fails). Logs FAILED, returns $false, never throws.
function Invoke-Step {
    param([Parameter(Position = 0)][string]$Name, [Parameter(Position = 1)][scriptblock]$Action, [switch]$RobocopyCodes)
    if ($DryRun) { Write-Log "WOULD: $Name"; return $false }
    $global:LASTEXITCODE = 0
    try {
        $out = & $Action 2>&1
        $errs = @($out | Where-Object { $_ -is [Management.Automation.ErrorRecord] -and $_.FullyQualifiedErrorId -notlike 'NativeCommandError*' })
        $failed = if ($RobocopyCodes) { $LASTEXITCODE -ge 8 } else { $LASTEXITCODE -ne 0 }
        if (-not $failed -and $errs.Count -eq 0) { return $true }
        Write-Log "FAILED: ${Name}: exit $LASTEXITCODE $(if ($errs.Count) { $errs[0] } else { ($out | Select-Object -Last 1) -join ' ' })"
    } catch { Write-Log "FAILED: ${Name}: $($_.Exception.Message)" }
    $State.Failures += $Name; return $false
}
function Test-IsAdmin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
function ConvertFrom-SecureText { param([Security.SecureString]$Secure); $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure); try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) } }

# ---- Accounts ----
function Get-LocalEnabledUsers { (Get-LocalUser | Where-Object Enabled).Name }
# Accounts that services, IIS app pools and scheduled tasks run as. Changing their passwords would break them.
function Get-InUseAccounts {
    (Get-CimInstance -ClassName Win32_Service).StartName
    $appcmd = "$env:windir\system32\inetsrv\appcmd.exe"; if (Test-Path $appcmd) { & $appcmd list apppool /text:processModel.userName }
    (Get-ScheduledTask).Principal.UserId
}
# Enabled local users minus $ExcludeUsers and in-use accounts. '.\bob', 'HOST\bob' and 'CORP\bob' all match 'bob'; -contains ignores case.
function Get-PasswordTargets {
    $skip = @(@($ExcludeUsers) + @(Get-InUseAccounts) | Where-Object { $_ } | ForEach-Object { $_ -replace '^.*\\' })
    @(Get-LocalEnabledUsers) | Where-Object { $skip -notcontains $_ }
}

# ---- Firewall ----
function Get-ListeningPorts {
    $proc = @{ n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } }
    @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object @{ n = 'Proto'; e = { 'TCP' } }, @{ n = 'Port'; e = { [int]$_.LocalPort } }, $proc) +
    @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object @{ n = 'Proto'; e = { 'UDP' } }, @{ n = 'Port'; e = { [int]$_.LocalPort } }, $proc) | Sort-Object Proto, Port -Unique
}
# Ports that already have an enabled inbound allow rule, e.g. 'TCP:80'. Only single port numbers count (not ranges or Any): it may over-warn, never under-warn.
function Get-InboundAllowPorts {
    Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | Get-NetFirewallPortFilter |
        ForEach-Object { $proto = "$($_.Protocol)".ToUpper(); @($_.LocalPort) -match '^\d+$' | ForEach-Object { "${proto}:$_" } }
}
# Ports open for the whole run: the live RDP port plus $KeepOpenTcp. Their rules are named HPCC4-Keep-TCP-<port>.
function Get-KeepPorts { @(@($State.RdpPort) + @($KeepOpenTcp) | ForEach-Object { [int]$_ } | Select-Object -Unique) }
# Adds inbound rule HPCC4-<Label>-<Proto>-<Port>. Label 'Block' blocks; 'Keep' and 'Allow' allow.
function Add-Rule {
    param([string]$Label, [string]$Proto, [int]$Port)
    $n = "HPCC4-$Label-$Proto-$Port"; $act = if ($Label -eq 'Block') { 'Block' } else { 'Allow' }
    if (Invoke-Step $n { New-NetFirewallRule -Name $n -DisplayName $n -Direction Inbound -Protocol $Proto -LocalPort $Port -Action $act }) { $State.RulesAdded += $n }
}
# Removes local inbound rules. -All: every rule except the built-in DHCP ones. Otherwise: only old HPCC4-* rules. Keep rules always stay.
function Remove-InboundRules {
    param([switch]$All)
    $keep = Get-KeepPorts | ForEach-Object { "HPCC4-Keep-TCP-$_" }
    $names = @(Get-NetFirewallRule -Direction Inbound -PolicyStore PersistentStore -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } |
        Where-Object { $keep -notcontains $_ -and $_ -notlike 'CoreNet-DHCP*' -and ($All -or $_ -like 'HPCC4-*') })
    if ($names.Count) { Invoke-Step "remove $($names.Count) inbound firewall rules" { Remove-NetFirewallRule -Name $names } }
}
function Enable-Firewall {
    param([switch]$BlockInbound)
    $prof = @{ Profile = 'Domain', 'Private', 'Public'; Enabled = 'True' }; if ($BlockInbound) { $prof.DefaultInboundAction = 'Block' }
    $State.FirewallOn = Invoke-Step 'firewall on' { Set-NetFirewallProfile @prof }
}

# ---- Steps, in run order ----
function Initialize-Setup {
    $rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction SilentlyContinue).PortNumber
    $State.RdpPort = if ($rdp) { [int]$rdp } else { 3389 }
    $State.IsDC = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -in 4, 5
    Invoke-Step 'create OutDir' { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
    Invoke-Step 'lock down OutDir' { icacls $OutDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' }
}
function Backup-Targets {
    $State.BackupDir = Join-Path $OutDir "backup\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    foreach ($p in $BackupPaths) {
        $item = Get-Item $p -ErrorAction SilentlyContinue; if (-not $item) { Write-Log "backup skip (missing): $p"; continue }
        # robocopy takes a folder plus what to copy: /E (everything) for a folder, or the file's name. The copy keeps the original path minus the drive colon.
        if ($item.PSIsContainer) { $src = $item.FullName.TrimEnd('\'); $what = '/E' } else { $src = $item.DirectoryName; $what = $item.Name }
        Invoke-Step "backup $p" { robocopy $src (Join-Path $State.BackupDir ($src -replace ':')) $what /R:1 /W:1 } -RobocopyCodes
    }
    $wfw = Join-Path $OutDir 'firewall-before.wfw'   # exported only once, so it always holds the original policy
    if (Test-Path $wfw) { Write-Log 'firewall-before.wfw exists, keeping the original' } else { Invoke-Step 'export firewall' { netsh advfirewall export $wfw } }
}
# Start of run: close every inbound port except RDP, $KeepOpenTcp and DHCP. Service ports reopen in Open-ServicePorts at the end.
function Set-FirewallLockdown {
    $keep = Get-KeepPorts; $State.Enable = $true; $State.Purge = $true
    if ($State.IsDC) { $State.Purge = $false; Write-Log 'WARNING: domain controller - NOT removing existing firewall rules (AD needs dynamic RPC ports).' }
    elseif (-not $DryRun -and -not (Test-Path (Join-Path $OutDir 'firewall-before.wfw'))) { $State.Purge = $false; Write-Log 'WARNING: no firewall backup (firewall-before.wfw) - NOT removing existing firewall rules.' }
    # Warn about listening ports that nothing will allow. Without a purge, existing allow rules still count.
    $covered = @(@($AllowTcp) + $keep | ForEach-Object { "TCP:$_" }) + @(@($AllowUdp) | ForEach-Object { "UDP:$_" })
    if (-not $State.Purge) { $covered += @(Get-InboundAllowPorts) }
    $State.Uncovered = @(Get-ListeningPorts | Where-Object { $covered -notcontains "$($_.Proto):$($_.Port)" })
    $State.Uncovered | ForEach-Object { Write-Log "WARNING: $($_.Proto) $($_.Port) ($($_.Process)) is listening but not covered - this service will be blocked once the firewall is on." }
    if ($State.Uncovered.Count -and -not $DryRun -and (Read-Host 'Uncovered ports found. Lock down the firewall anyway? y/N') -ne 'y') {
        $State.Enable = $false; $State.Purge = $false; Write-Log 'Firewall left as it is; HPCC4 rules will still be added at the end.'
    }
    # Add the keep rules BEFORE removing anything, so RDP never has a gap. Keep rules that already exist are left alone.
    $keep | Where-Object { -not (Get-NetFirewallRule -Name "HPCC4-Keep-TCP-$_" -ErrorAction SilentlyContinue) } | ForEach-Object { Add-Rule 'Keep' 'TCP' $_ }
    if ($State.Purge) { Remove-InboundRules -All; Enable-Firewall -BlockInbound }
}
# Deletes local accounts that aren't authorized. Always kept: built-ins (ID < 1000: Administrator even if renamed, Guest, etc.),
# you, $AuthorizedUsers, $ExcludeUsers, and accounts that services, app pools or tasks run as. Deleting can't be undone,
# so each account's SID and groups are printed first, in case you need to recreate it.
function Remove-UnauthorizedUsers {
    if ($State.IsDC) { Write-Log 'Skipping account removal: this is a domain controller.'; return }
    if (-not $AuthorizedUsers) { Write-Log 'Skipping account removal: $AuthorizedUsers is empty.'; return }
    $keep = @(@($AuthorizedUsers) + @($ExcludeUsers) + @(Get-InUseAccounts) + $env:USERNAME | Where-Object { $_ } | ForEach-Object { $_ -replace '^.*\\' })
    $doomed = @(Get-LocalUser | Where-Object { [int]($_.SID.Value -split '-')[-1] -ge 1000 -and $keep -notcontains $_.Name })
    if (-not $doomed.Count) { Write-Log 'No unauthorized local accounts found.'; return }
    Write-Log "UNAUTHORIZED accounts to DELETE: $(($doomed | ForEach-Object { $_.Name }) -join ', ')"
    if ($DryRun) { Write-Log 'WOULD: delete the accounts above'; return }
    if ((Read-Host 'DELETE these accounts permanently? y/N') -ne 'y') { return }
    foreach ($u in $doomed) {
        $groups = try { (Get-LocalGroup | Where-Object { @((Get-LocalGroupMember $_ -ErrorAction SilentlyContinue).SID.Value) -contains $u.SID.Value }).Name -join ',' } catch { '?' }
        Write-Log "Deleting $($u.Name) (SID $($u.SID.Value), groups: $groups)"
        if (Invoke-Step "delete account $($u.Name)" { Remove-LocalUser -SID $u.SID }) { $State.Deleted += $u.Name }
    }
}
function Set-LocalPasswords {
    if ($State.IsDC) { Write-Log 'Skipping password changes: this is a domain controller.'; return }
    $targets = @(Get-PasswordTargets); Write-Log "Password targets: $($targets -join ', ')"
    if ($DryRun) { Write-Log 'WOULD: change passwords for targets above'; return }
    if ((Read-Host 'Change these passwords? y/N') -ne 'y') { return }
    # The password stays a SecureString: never logged, echoed or put on a command line. Plain text exists only
    # for a moment, inline, to check that the two entries match (case-sensitively).
    $pw = $null
    for ($i = 0; $i -lt 3 -and -not $pw; $i++) {
        $s1 = Read-Host 'New password (blank to skip)' -AsSecureString; if ($s1.Length -eq 0) { return }
        $s2 = Read-Host 'Confirm password' -AsSecureString
        if ((ConvertFrom-SecureText $s1) -ceq (ConvertFrom-SecureText $s2)) { $pw = $s1 } else { Write-Log 'Passwords did not match, try again.' }
    }
    if (-not $pw) { Write-Log 'Password entry failed after 3 tries.'; return }
    foreach ($u in $targets) { if (Invoke-Step "password $u" { Set-LocalUser -Name $u -Password $pw }) { $State.Changed += $u } }
    $pw = $s1 = $s2 = $null
    Write-Log "Changed accounts: $($State.Changed -join ', ')"; Write-Log 'SUBMIT PASSWORD CHANGES TO THE SCOREBOARD.'
}
# Downloads (if a URL) and checks the tools zip, then unzips it into the already-locked ToolsDir.
function Expand-ToolsZip {
    $zip = $ToolsZip
    if ($ToolsZip -match '^https?://') {
        $zip = Join-Path $OutDir 'tools.zip'   # use it only if THIS download worked, never a stale one from an earlier run
        if (-not (Invoke-Step 'download tools zip' { Invoke-WebRequest $ToolsZip -OutFile $zip -UseBasicParsing })) { return }
    }
    if (-not (Test-Path $zip)) { Write-Log "Tools zip not found: $zip"; return }
    if ($ToolsZipSha256 -and (Get-FileHash $zip -Algorithm SHA256).Hash -ne $ToolsZipSha256.Trim()) { Write-Log 'Tools zip hash MISMATCH - rejected.'; $State.HashChecked = 'MISMATCH - rejected'; return }
    $State.HashChecked = if ($ToolsZipSha256) { 'ok' } else { 'not set' }
    $State.ToolsInstalled = Invoke-Step 'extract tools into ToolsDir' { Expand-Archive -Path $zip -DestinationPath $ToolsDir -Force }   # -Force overwrites older copies
}
function Install-Tools {
    if (-not $ToolsZip -and -not $AvInstallerUrl) { Write-Log 'No tools zip or AV installer set; skipping tools.'; return }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12   # GitHub needs TLS 1.2
    $ProgressPreference = 'SilentlyContinue'   # PowerShell 5.1 downloads are many times slower with the progress bar on
    # Lock ToolsDir BEFORE anything goes in, so every file inherits "only admins can write" and nobody can plant a fake tool.
    Invoke-Step 'create ToolsDir' { New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null }
    if (-not (Invoke-Step 'lock down ToolsDir' { icacls $ToolsDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' }) -and -not $DryRun) { return }
    if ($ToolsZip) { Expand-ToolsZip }
    # AV installer: no hash to pin (the vendor updates it), so it only gets opened later if it carries a valid digital signature.
    if ($AvInstallerUrl) {
        $av = Join-Path $ToolsDir (Split-Path $AvInstallerUrl -Leaf)
        if (Invoke-Step "download $(Split-Path $AvInstallerUrl -Leaf)" { Invoke-WebRequest $AvInstallerUrl -OutFile $av -UseBasicParsing }) {
            $sig = Get-AuthenticodeSignature $av
            if ($sig.Status -eq 'Valid') { $State.AvInstaller = $av; Write-Log "AV installer signed by: $($sig.SignerCertificate.Subject)" }
            else { Write-Log "WARNING: $av signature is $($sig.Status) - it will NOT be opened." }
        }
    }
    # Append (never prepend) ToolsDir to the machine PATH, keeping %vars% in the other entries unexpanded.
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'; $path = (Get-Item $key).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    if (@($path -split ';' | ForEach-Object { $_.TrimEnd('\') }) -notcontains $ToolsDir.TrimEnd('\')) { Invoke-Step 'add ToolsDir to PATH' { New-ItemProperty $key -Name Path -Value "$path;$ToolsDir" -PropertyType ExpandString -Force | Out-Null } }
    Invoke-Step 'accept Sysinternals EULA' { New-Item 'HKCU:\Software\Sysinternals' -ErrorAction SilentlyContinue | Out-Null; New-ItemProperty 'HKCU:\Software\Sysinternals' -Name EulaAccepted -Value 1 -PropertyType DWord -Force | Out-Null }
    $exe = Join-Path $ToolsDir 'Sysmon64.exe'; $cfg = Join-Path $ToolsDir 'sysmonconfig.xml'
    if ($InstallSysmon -and (Test-Path $exe) -and (Test-Path $cfg)) {
        if (Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue) { Invoke-Step 'update Sysmon config' { & $exe -c $cfg } } else { Invoke-Step 'install Sysmon' { & $exe -accepteula -i $cfg } }
    }
}
# One ACL save file per path: the path made filename-safe plus a short hash, e.g. acl-C__Windows_System32_drivers_etc_hosts-1a2b3c4d.txt
function Get-AclSaveFile {
    param([string]$Path)
    $hash = -join ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Path.ToLowerInvariant()))[0..3] | ForEach-Object { $_.ToString('x2') })
    Join-Path $OutDir "acl-$($Path -replace '[:\\/]', '_')-$hash.txt"
}
function Test-EveryoneDeny { param([string]$Path); try { [bool]((Get-Acl $Path).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Value -eq 'S-1-1-0' }) } catch { $false } }
# Lock: save the original ACL once, set read-only, then deny Everyone write/delete. WRITE_DAC isn't denied, so the lock can always be undone.
function Lock-Paths {
    foreach ($path in $LockPaths) {
        $item = Get-Item $path -ErrorAction SilentlyContinue; if (-not $item) { Write-Log "lock skip (missing): $path"; continue }
        $save = Get-AclSaveFile $path; $isDir = $item.PSIsContainer
        # Never overwrite a save (a 2nd run would save the LOCKED ACL), and never lock a path whose save failed (-Unlock couldn't undo it).
        if (-not (Test-Path $save) -and -not (Invoke-Step "save ACL $path" { if ($isDir) { icacls $path /save $save /T } else { icacls $path /save $save }; Set-Content ([IO.Path]::ChangeExtension($save, '.path')) $path }) -and -not $DryRun) { continue }
        Invoke-Step "attrib +R $path" { attrib +R $path }   # before the deny, which blocks attribute changes
        if (Test-EveryoneDeny $path) { $State.Locked += $path; continue }
        $inherit = if ($isDir) { '(OI)(CI)' } else { '' }
        if (Invoke-Step "deny Everyone $path" { icacls $path /deny "*S-1-1-0:$inherit(W,D,DC)" }) { $State.Locked += $path }
    }
}
# Unlock: restore each saved ACL, clear read-only, then rename the save files to *.restored so the next lock saves a fresh ACL.
function Unlock-Paths {
    foreach ($save in @(Get-ChildItem $OutDir -Filter 'acl-*.txt' -ErrorAction SilentlyContinue)) {
        $pathFile = [IO.Path]::ChangeExtension($save.FullName, '.path'); if (-not (Test-Path $pathFile)) { continue }
        $target = (Get-Content $pathFile -Raw).Trim()
        # icacls saved names relative to the parent folder. Only rename after a good restore, so a failed one can be retried.
        if (-not (Invoke-Step "restore ACL $target" { icacls (Split-Path $target -Parent) /restore $save.FullName })) { continue }
        Invoke-Step "unlock attrib $target" { attrib -R $target }
        Invoke-Step "rename save files $target" { Rename-Item $save.FullName "$($save.Name).restored"; Rename-Item $pathFile "$(Split-Path $pathFile -Leaf).restored" }
    }
}
# End of run (always runs, even after a failure or Ctrl+C): open the scored-service ports from the tunables.
function Open-ServicePorts {
    $keep = Get-KeepPorts
    if (-not $State.Purge) { Remove-InboundRules }   # a purge already removed the old HPCC4 rules
    @($AllowTcp) | Select-Object -Unique | Where-Object { $keep -notcontains $_ } | ForEach-Object { Add-Rule 'Allow' 'TCP' $_ }
    @($AllowUdp) | Select-Object -Unique | ForEach-Object { Add-Rule 'Allow' 'UDP' $_ }
    # Windows block rules beat allow rules, so never block a port that is allowed, kept open or used by RDP.
    foreach ($p in @($BlockTcp)) { if ((@($AllowTcp) + $keep) -contains $p) { Write-Log "REFUSED block TCP $p - it is allowed, kept open or the RDP port"; $State.BlocksRefused += "TCP:$p" } else { Add-Rule 'Block' 'TCP' $p } }
    foreach ($p in @($BlockUdp)) { if (@($AllowUdp) -contains $p) { Write-Log "REFUSED block UDP $p - it is allowed"; $State.BlocksRefused += "UDP:$p" } else { Add-Rule 'Block' 'UDP' $p } }
    if ($State.Enable -and -not $State.FirewallOn) { Enable-Firewall }
}
function Write-Summary {
    Write-Log "Backup: $($State.BackupDir) | Uncovered ports: $($State.Uncovered.Count) | Old inbound rules removed: $($State.Purge) | Firewall on: $($State.FirewallOn)"
    Write-Log "Rules added: $($State.RulesAdded -join ', ') | Blocks refused: $($State.BlocksRefused -join ', ') | Accounts deleted: $($State.Deleted -join ', ') | Passwords changed: $($State.Changed -join ', ')"
    Write-Log "Tools installed: $($State.ToolsInstalled) | Hash check: $($State.HashChecked) | AV installer: $($State.AvInstaller) | Locked: $($State.Locked -join ', ') | Failures: $($State.Failures -join ', ')"
}
# Clears PS history, wipes all Windows Event Logs, then schedules the script and its directory for deletion after exit.
function Invoke-Cleanup {
    if ($DryRun) { Write-Log 'WOULD: clear PS history, clear event logs, self-delete script and directory'; return }
    Invoke-Step 'clear PS history' { Remove-Item (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue }
    Invoke-Step 'clear event logs' {
        Get-WinEvent -ListLog * | ForEach-Object {
            try { [Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) } catch {}
        }
    }
    $scriptPath = $PSCommandPath
    $scriptDir  = $PSScriptRoot
    Write-Log "Scheduling self-delete: $scriptPath and $scriptDir"
    cmd /c "ping -n 2 127.0.0.1 > nul & del /f /q `"$scriptPath`" & rmdir /s /q `"$scriptDir`""
}
function Main {
    if (-not (Test-IsAdmin)) { Write-Log 'Must be run elevated (as Administrator). Exiting.'; exit 1 }
    $null = Initialize-Setup   # $null = hides Invoke-Step's True/False results from the console
    if ($Unlock) { $null = Unlock-Paths; return }
    $null = Backup-Targets
    # finally: the service ports reopen even if a step fails or you press Ctrl+C, so services never stay closed.
    try { $null = Set-FirewallLockdown; $null = Remove-UnauthorizedUsers; $null = Set-LocalPasswords; $null = Install-Tools; $null = Lock-Paths }
    finally { $null = Open-ServicePorts; Write-Summary }
    # Only after a normal finish, with services back up: open the AV installer for you to click through (it needs internet).
    if ($State.AvInstaller) { Write-Log "Opening the AV installer: $($State.AvInstaller)"; $null = Invoke-Step 'open AV installer' { Start-Process $State.AvInstaller } }
    if ($Cleanup) { $null = Invoke-Cleanup }
}
if ($MyInvocation.InvocationName -ne '.') { Main }
