param([switch]$DryRun, [switch]$Unlock)
# assembly-4 (Server 2022): scored RDP (jmoney) + Jenkins 8080. Run elevated from this folder: LGPO.exe and GPO\ sit next to it.
$ExpectedBuild  = 20348          # refuses to run on any other OS build (wrong folder = wrong box)
$KeepOpenTcp    = @()            # inbound open for the whole run, besides the live RDP port
$AllowTcp       = @(3389, 8080)  # inbound opened at the END of the run; everything else stays blocked
$AllowUdp       = @()
$BlockTcp       = @()
$BlockUdp       = @()
$RunOutTcp      = @(53, 80, 443) # outbound to ANY host only while the script runs (downloads); closed at the end
$RunOutUdp      = @(53)
$AllowOut       = @('172.16.4.5', '172.16.4.40:3306')   # outbound kept after the run: 'host', 'host:port' (TCP) or 'host:port/udp'. .5 = blackbox (OpenObserve logs), .40:3306 = Jenkins' MySQL backup from manifest
$ExcludeUsers   = @()
$AuthorizedUsers = @('plinktern', 'jmoney')
$RdpOnlyUsers   = @('jmoney')    # enabled, in Remote Desktop Users, and taken OUT of Administrators
$DisableUsers   = @()
$ToolsDir       = 'C:\Tools'
$ToolsZip       = 'https://github.com/joshjwalter/Pwneigh-Tools/archive/refs/heads/main.zip'
$ToolsZipSha256 = ''
$AvInstallerUrl = 'https://free.360totalsecurity.com/totalsecurity/360TS_Setup_Mini.exe'
$InstallSysmon  = $false
$BackupPaths    = @('C:\Windows\System32\drivers\etc\hosts')
$LockPaths      = @('C:\Windows\System32\drivers\etc\hosts')
$OutDir         = 'C:\HPCC4'
$DisableServices = @()
$ApplyStigGpo      = $true
$ApplyDefenderStig = $false      # off: 360TS is the AV, and two real-time AVs fight
$ProgressPreference = 'SilentlyContinue'; $WarningPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$Start = Get-Date
$State = @{ Domain = ''; RdpPort = 3389; Purge = $false; FirewallOn = $false; Phases = @(); Failures = @(); Would = @(); Deleted = @(); Disabled = @(); RdpOnly = @(); PwTargets = @(); Changed = @(); OutKept = @(); AvLaunched = $false; Persistence = @() }

function Invoke-Step {
    param([Parameter(Position = 0)][string]$Name, [Parameter(Position = 1)][scriptblock]$Action, [switch]$RobocopyCodes)
    if ($DryRun) { $State.Would += $Name; return $false }
    $global:LASTEXITCODE = 0
    try {
        $out = & $Action 2>&1
        $errs = @($out | Where-Object { $_ -is [Management.Automation.ErrorRecord] -and $_.FullyQualifiedErrorId -notlike 'NativeCommandError*' })
        $failed = if ($RobocopyCodes) { $LASTEXITCODE -ge 8 } else { $LASTEXITCODE -ne 0 }
        if (-not $failed -and $errs.Count -eq 0) { return $true }
        $msg = "exit $LASTEXITCODE $(if ($errs.Count) { $errs[0] } else { ($out | Select-Object -Last 1) -join ' ' })"
    } catch { $msg = $_.Exception.Message }
    $State.Failures += "${Name}: $msg"; return $false
}
function Skip { param([string]$Why) $script:SkipWhy = $Why }
function Invoke-Phase {
    param([string]$Name, [scriptblock]$Action)
    $f = $State.Failures.Count; $w = $State.Would.Count; $script:SkipWhy = ''
    try { & $Action 2>&1 | ForEach-Object { if ($_ -is [Management.Automation.ErrorRecord]) { $State.Failures += "$_" } } }
    catch { $State.Failures += $_.Exception.Message }
    $State.Phases += [pscustomobject]@{ Name = $Name; Skip = $script:SkipWhy; Failed = @($State.Failures | Select-Object -Skip $f); Would = @($State.Would | Select-Object -Skip $w) }
}
function Lock-AdminOnlyAcl {
    param([string]$Path, [string[]]$ExtraGrants = @())
    icacls $Path /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' @ExtraGrants
}

function Get-KeepPorts { @(@($State.RdpPort) + @($KeepOpenTcp) | ForEach-Object { [int]$_ } | Select-Object -Unique) }
function Add-Rule {
    param([string]$Label, [string]$Proto, [int]$Port)
    $n = "HPCC4-$Label-$Proto-$Port"; $act = if ($Label -eq 'Block') { 'Block' } else { 'Allow' }
    Invoke-Step $n { New-NetFirewallRule -Name $n -DisplayName $n -Direction Inbound -Protocol $Proto -LocalPort $Port -Action $act }
}
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
# Outbound allow rules by name: HPCC4-Run-* (any host, removed at the end of the run) and HPCC4-Out-* ($AllowOut + a domain member's DCs, kept).
function Get-OutboundRules {
    $rules = [ordered]@{}
    @($RunOutTcp) | ForEach-Object { $rules["HPCC4-Run-TCP-$_"] = @{ Protocol = 'TCP'; RemotePort = $_ } }
    @($RunOutUdp) | ForEach-Object { $rules["HPCC4-Run-UDP-$_"] = @{ Protocol = 'UDP'; RemotePort = $_ } }
    $dcs = @()
    if ($State.Domain) { $dcs = @(Resolve-DnsName -Name $State.Domain -Type A -DnsOnly -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress } | Where-Object { $_ }) }
    foreach ($e in @(@($AllowOut) + $dcs | Where-Object { $_ })) {
        if ($e -notmatch '^(?<h>[^:/]+)(:(?<p>\d+)(?<u>/udp)?)?$') { $State.Failures += "outbound ${e}: not host, host:port or host:port/udp"; continue }
        $m = @{ RemoteAddress = $(if ($Matches.h -eq '*') { 'Any' } else { $Matches.h }) }
        if ($Matches.p) { $m.RemotePort = $Matches.p; $m.Protocol = if ($Matches.u) { 'UDP' } else { 'TCP' } }
        $rules["HPCC4-Out-$($e -replace '^\*', 'Any' -replace '[^\w.]', '_')"] = $m
    }
    $rules
}

function Initialize-Setup {
    $rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction SilentlyContinue).PortNumber
    $State.RdpPort = if ($rdp) { [int]$rdp } else { 3389 }
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $State.Domain = if ($cs.PartOfDomain) { $cs.Domain } else { '' }
    Invoke-Step 'create OutDir' { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
    Invoke-Step 'lock down OutDir' { Lock-AdminOnlyAcl $OutDir }
}
function Backup-Targets {
    $dir = Join-Path $OutDir "backup\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    foreach ($p in $BackupPaths) {
        $item = Get-Item $p -ErrorAction SilentlyContinue; if (-not $item) { continue }
        if ($item.PSIsContainer) { $src = $item.FullName.TrimEnd('\'); $what = '/E' } else { $src = $item.DirectoryName; $what = $item.Name }
        Invoke-Step "backup $p" { robocopy $src (Join-Path $dir ($src -replace ':')) $what /R:1 /W:1 } -RobocopyCodes
    }
    $wfw = Join-Path $OutDir 'firewall-before.wfw'
    if (-not (Test-Path $wfw)) { Invoke-Step 'export firewall' { netsh advfirewall export $wfw } }
}
function Set-FirewallLockdown {
    $State.Purge = $true
    Get-KeepPorts | Where-Object { -not (Get-NetFirewallRule -Name "HPCC4-Keep-TCP-$_" -ErrorAction SilentlyContinue) } | ForEach-Object { Add-Rule 'Keep' 'TCP' $_ }
    Remove-InboundRules -All
    Enable-Firewall -BlockInbound
}
function Set-OutboundLockdown {
    $rules = Get-OutboundRules
    foreach ($n in @($rules.Keys)) {
        $match = $rules[$n]
        if (-not (Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue)) { Invoke-Step $n { New-NetFirewallRule -Name $n -DisplayName $n -Direction Outbound -Action Allow @match } }
    }
    $State.OutKept = @($rules.Keys | Where-Object { $_ -like 'HPCC4-Out-*' })
    $names = @(Get-NetFirewallRule -Direction Outbound -PolicyStore PersistentStore -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } |
        Where-Object { $rules.Keys -notcontains $_ -and $_ -notlike 'CoreNet-*' })
    if ($names.Count) { Invoke-Step "remove $($names.Count) outbound firewall rules" { Remove-NetFirewallRule -Name $names } }
    Invoke-Step 'block outbound by default' { Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultOutboundAction Block }
}
function Close-RunOutbound {
    $names = @(Get-NetFirewallRule -Direction Outbound -PolicyStore PersistentStore -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } | Where-Object { $_ -like 'HPCC4-Run-*' })
    if (-not $names.Count -and -not $DryRun) { Skip 'no run-time outbound rules'; return }
    Invoke-Step "remove run-time outbound rules $($names -join ', ')" { Remove-NetFirewallRule -Name $names }
}
function Remove-UnauthorizedUsers {
    if (-not $AuthorizedUsers) { Skip '$AuthorizedUsers is empty'; return }
    $keep = @(@($AuthorizedUsers) + @($RdpOnlyUsers) + @($ExcludeUsers))
    foreach ($u in @(Get-LocalUser | Where-Object { [int]($_.SID.Value -split '-')[-1] -ge 1000 -and $keep -notcontains $_.Name })) {
        if (Invoke-Step "delete $($u.Name) (SID $($u.SID.Value))" { Remove-LocalUser -SID $u.SID }) { $State.Deleted += $u.Name }
    }
}
function Disable-Accounts {
    foreach ($u in @(Get-LocalUser | Where-Object { $_.Enabled -and $ExcludeUsers -notcontains $_.Name -and ($DisableUsers -contains $_.Name -or $_.SID.Value -match '-50[134]$') })) {
        if (Invoke-Step "disable $($u.Name)" { Disable-LocalUser -SID $u.SID }) { $State.Disabled += $u.Name }
    }
}
# Scored login accounts: RDP must keep working (Remote Desktop Users), admin rights must not. Never applied to you.
function Set-RdpOnlyUsers {
    if (-not $RdpOnlyUsers) { Skip '$RdpOnlyUsers is empty'; return }
    foreach ($n in @($RdpOnlyUsers)) {
        $u = Get-LocalUser -Name $n -ErrorAction SilentlyContinue
        if (-not $u) { $State.Failures += "RDP-only user $n does not exist"; continue }
        if ($n -eq $env:USERNAME) { $State.Failures += "RDP-only user $n is the account running this script - left as it is"; continue }
        if (-not $u.Enabled) { Invoke-Step "enable $n" { Enable-LocalUser -SID $u.SID } }
        $rdp = Invoke-Step "$n into Remote Desktop Users" { try { Add-LocalGroupMember -SID 'S-1-5-32-555' -Member $u -ErrorAction Stop } catch [Microsoft.PowerShell.Commands.MemberExistsException] {} }
        $adm = Invoke-Step "$n out of Administrators" { try { Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $u -ErrorAction Stop } catch [Microsoft.PowerShell.Commands.MemberNotFoundException] {} }
        if ($rdp -and $adm) { $State.RdpOnly += $n }
    }
}
function Set-LocalPasswords {
    $State.PwTargets = @((Get-LocalUser | Where-Object Enabled).Name | Where-Object { @($ExcludeUsers) -notcontains $_ })
    if ($DryRun) { $State.Would += "change passwords: $($State.PwTargets -join ', ')"; return }
    $pw = Read-Host "New password for $($State.PwTargets.Count) accounts (blank to skip)" -AsSecureString
    if ($pw.Length -eq 0) { Skip 'no password entered'; return }
    foreach ($u in $State.PwTargets) { if (Invoke-Step "password $u" { Set-LocalUser -Name $u -Password $pw }) { $State.Changed += $u } }
    $pw = $null
}
# Downloads the AV installer into the admin-only OutDir and opens it right away, so you click through it while the
# script carries on. Outbound 80/443 stays open until you confirm it's done (at the end of the run).
function Start-AvInstaller {
    if (-not $AvInstallerUrl) { Skip '$AvInstallerUrl is empty'; return }
    $av = Join-Path $OutDir (Split-Path $AvInstallerUrl -Leaf)
    if (-not (Invoke-Step 'download AV installer' { Invoke-WebRequest $AvInstallerUrl -OutFile $av -UseBasicParsing })) { return }
    $sig = Get-AuthenticodeSignature $av
    if ($sig.Status -ne 'Valid') { $State.Failures += "AV installer signature is $($sig.Status) - NOT opened: $av"; return }
    if (Invoke-Step "open AV installer (signed by $($sig.SignerCertificate.Subject))" { Start-Process $av }) { $State.AvLaunched = $true }
}
function Set-RdpNla {
    Invoke-Step 'RDP NLA on' { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord }
}
function Disable-ExtraServices {
    if (-not $DisableServices) { Skip '$DisableServices is empty'; return }
    foreach ($svc in @($DisableServices)) { Invoke-Step "stop + disable $svc" { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue; Set-Service -Name $svc -StartupType Disabled } }
}

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
$script:PersistenceRegistrySources = @(
    @{ Type = 'Run'; Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
    @{ Type = 'Run'; Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
    @{ Type = 'Run'; Key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
    @{ Type = 'Run'; Key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
    @{ Type = 'Winlogon'; Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Values = 'Shell', 'Userinit' },
    @{ Type = 'AppInit/AppCert'; Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; Values = 'AppInit_DLLs', 'AppCertDLLs' },
    @{ Type = 'LSA-Package'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Values = 'Security Packages', 'Notification Packages', 'Authentication Packages' }
)
$script:PsSyntheticProps = 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider'
function Get-PersistenceReport {
    $mk = { param($Type, $Name, $Cmd) [pscustomobject]@{ Type = $Type; Name = $Name; Command = "$Cmd"; Suspicious = (Test-SuspiciousPath "$Cmd") } }
    $mySid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    $found = @(
        foreach ($src in $script:PersistenceRegistrySources) {
            try {
                (Get-ItemProperty -Path $src.Key -ErrorAction Stop).PSObject.Properties |
                    Where-Object { $_.Name -notin $script:PsSyntheticProps -and (-not $src.Values -or $_.Name -in $src.Values) } |
                    ForEach-Object { & $mk $src.Type $_.Name $_.Value }
            } catch {}
        }
        foreach ($sid in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' -and $_.PSChildName -ne $mySid } | Select-Object -ExpandProperty PSChildName)) {
            foreach ($sub in 'Run', 'RunOnce') {
                try { (Get-ItemProperty -Path "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\$sub" -ErrorAction Stop).PSObject.Properties |
                    Where-Object { $_.Name -notin $script:PsSyntheticProps } | ForEach-Object { & $mk 'Run' "$($_.Name) ($sid)" $_.Value } } catch {}
            }
        }
        try {
            Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction Stop | ForEach-Object {
                $d = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
                if ($d) { & $mk 'IFEO-Debugger' $_.PSChildName $d }
            }
        } catch {}
        try {
            Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' -ErrorAction Stop | ForEach-Object {
                $s = (Get-ItemProperty $_.PSPath -Name StubPath -ErrorAction SilentlyContinue).StubPath
                if ($s) { & $mk 'ActiveSetup' $_.PSChildName $s }
            }
        } catch {}
        try { Get-ScheduledTask -ErrorAction Stop | ForEach-Object { & $mk 'ScheduledTask' "$($_.TaskPath)$($_.TaskName)" ((@($_.Actions.Execute) + @($_.Actions.Arguments)) -join ' ') } } catch {}
        try {
            Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName } | ForEach-Object {
                if ($_.PathName -match '(?i)\\svchost\.exe\b') {
                    $dll = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)\Parameters" -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll
                    if ($dll) { & $mk 'Service (svchost)' $_.Name $dll }
                } elseif ($_.PathName -notmatch '(?i)\\Windows\\|\\Program Files') { & $mk 'Service' $_.Name $_.PathName }
            }
        } catch {}
        try { Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object { & $mk 'WMI-Subscription' "$($_.Filter)" "$($_.Consumer)" } } catch {}
        foreach ($dir in @(Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
            $sf = Join-Path $dir.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
            try { Get-ChildItem -Path $sf -File -ErrorAction Stop | ForEach-Object { & $mk 'StartupFolder' "$($dir.Name)\$($_.Name)" $_.FullName } } catch {}
        }
        try { Get-ChildItem -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -File -ErrorAction Stop | ForEach-Object { & $mk 'StartupFolder' "AllUsers\$($_.Name)" $_.FullName } } catch {}
    )
    $State.Persistence = $found
    Invoke-Step 'write persistence report' { $found | Format-Table -AutoSize | Out-String -Width 4096 | Set-Content -Path (Join-Path $OutDir 'persistence.txt') }
}

function Backup-LocalPolicy {
    param([string]$Lgpo)
    $dir = Join-Path $OutDir 'gpo-before'
    if (Test-Path $dir) { return }
    Invoke-Step 'backup local policy (LGPO)' { New-Item -ItemType Directory -Path $dir | Out-Null; & $Lgpo /b $dir /n 'gpo-before' }
    Invoke-Step 'backup security policy' { secedit /export /cfg (Join-Path $dir 'secpol-before.inf') /quiet }
    Invoke-Step 'backup audit policy' { auditpol /backup "/file:$(Join-Path $dir 'audit-before.csv')" }
}
# Applies GPO\OS (this box's STIG baseline) and, if on, GPO\Defender from this script's folder, then deletes GPO\ (it names the renamed admin).
function Install-DodGpo {
    $dir = Join-Path $PSScriptRoot 'GPO'; $lgpo = Join-Path $PSScriptRoot 'LGPO.exe'
    if (-not (Test-Path $dir)) { Skip "no GPO folder at $dir (already applied and deleted?)"; return }
    if (-not (Test-Path $lgpo)) { Skip "no LGPO.exe at $lgpo"; return }
    $folders = @()
    if ($ApplyStigGpo) { $folders += 'OS' }
    if ($ApplyDefenderStig -and (Get-Service -Name WinDefend -ErrorAction SilentlyContinue)) { $folders += 'Defender' }
    $backups = @(foreach ($f in $folders) { Get-ChildItem -Path (Join-Path $dir $f) -Recurse -Filter 'Backup.xml' -ErrorAction SilentlyContinue | ForEach-Object { $_.Directory.FullName } })
    if (-not $backups.Count) { Skip 'nothing to apply'; return }
    Backup-LocalPolicy $lgpo
    foreach ($b in $backups) { Invoke-Step "LGPO apply $(Split-Path $b -Leaf)" { & $lgpo /g $b } }
    Invoke-Step 'gpupdate /force' { gpupdate /force }
    Invoke-Step "delete GPO folder $dir" { Remove-Item $dir -Recurse -Force }
}
function Install-Tools {
    if (-not $ToolsZip) { Skip '$ToolsZip is empty'; return }
    Invoke-Step 'create ToolsDir' { New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null }
    Invoke-Step 'lock down ToolsDir' { Lock-AdminOnlyAcl $ToolsDir @('*S-1-5-32-545:(OI)(CI)RX') }
    $zip = $ToolsZip
    if ($ToolsZip -match '^https?://') {
        $zip = Join-Path $OutDir 'tools.zip'
        if (-not (Invoke-Step 'download tools zip' { Invoke-WebRequest $ToolsZip -OutFile $zip -UseBasicParsing })) { return }
    }
    if ($ToolsZipSha256 -and (Get-FileHash $zip -Algorithm SHA256).Hash -ne $ToolsZipSha256.Trim()) { $State.Failures += 'tools zip SHA256 mismatch - not extracted'; return }
    # Every file lands at the root of ToolsDir, whatever folders the zip has (a GitHub repo zip nests them).
    $tmp = Join-Path $OutDir 'tools-unzip'
    Invoke-Step 'extract tools zip' {
        if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        Get-ChildItem $tmp -Recurse -File | Copy-Item -Destination $ToolsDir -Force
        Remove-Item $tmp -Recurse -Force
    }
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'; $path = (Get-Item $key).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    if (@($path -split ';' | ForEach-Object { $_.TrimEnd('\') }) -notcontains $ToolsDir.TrimEnd('\')) { Invoke-Step 'add ToolsDir to PATH' { New-ItemProperty $key -Name Path -Value "$path;$ToolsDir" -PropertyType ExpandString -Force | Out-Null } }
    Invoke-Step 'accept Sysinternals EULA' { New-Item 'HKCU:\Software\Sysinternals' -ErrorAction SilentlyContinue | Out-Null; New-ItemProperty 'HKCU:\Software\Sysinternals' -Name EulaAccepted -Value 1 -PropertyType DWord -Force | Out-Null }
    $exe = Join-Path $ToolsDir 'Sysmon64.exe'; $cfg = Join-Path $ToolsDir 'sysmonconfig.xml'
    if ($InstallSysmon -and (Test-Path $exe) -and (Test-Path $cfg)) {
        if (Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue) { Invoke-Step 'update Sysmon config' { & $exe -c $cfg } } else { Invoke-Step 'install Sysmon' { & $exe -accepteula -i $cfg } }
    }
}

function Get-AclSaveFile {
    param([string]$Path)
    $hash = -join ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Path.ToLowerInvariant()))[0..3] | ForEach-Object { $_.ToString('x2') })
    Join-Path $OutDir "acl-$($Path -replace '[:\\/]', '_')-$hash.txt"
}
function Lock-Paths {
    foreach ($path in $LockPaths) {
        $item = Get-Item $path -ErrorAction SilentlyContinue; if (-not $item) { continue }
        $save = Get-AclSaveFile $path; $isDir = $item.PSIsContainer
        if (-not (Test-Path $save)) { Invoke-Step "save ACL $path" { if ($isDir) { icacls $path /save $save /T } else { icacls $path /save $save }; Set-Content ([IO.Path]::ChangeExtension($save, '.path')) $path } }
        Invoke-Step "attrib +R $path" { attrib +R $path }
        $inherit = if ($isDir) { '(OI)(CI)' } else { '' }
        Invoke-Step "deny Everyone $path" { icacls $path /deny "*S-1-1-0:$inherit(W,D,DC)" }
    }
}
function Unlock-Paths {
    foreach ($save in @(Get-ChildItem $OutDir -Filter 'acl-*.txt' -ErrorAction SilentlyContinue)) {
        $pathFile = [IO.Path]::ChangeExtension($save.FullName, '.path'); if (-not (Test-Path $pathFile)) { continue }
        $target = (Get-Content $pathFile -Raw).Trim()
        if (-not (Invoke-Step "restore ACL $target" { icacls (Split-Path $target -Parent) /restore $save.FullName })) { continue }
        Invoke-Step "unlock attrib $target" { attrib -R $target }
        Invoke-Step "rename save files $target" { Rename-Item $save.FullName "$($save.Name).restored"; Rename-Item $pathFile "$(Split-Path $pathFile -Leaf).restored" }
    }
}
function Open-ServicePorts {
    $keep = Get-KeepPorts
    if (-not $State.Purge) { Remove-InboundRules }
    @($AllowTcp) | Select-Object -Unique | Where-Object { $keep -notcontains $_ } | ForEach-Object { Add-Rule 'Allow' 'TCP' $_ }
    @($AllowUdp) | Select-Object -Unique | ForEach-Object { Add-Rule 'Allow' 'UDP' $_ }
    @($BlockTcp) | ForEach-Object { Add-Rule 'Block' 'TCP' $_ }
    @($BlockUdp) | ForEach-Object { Add-Rule 'Block' 'UDP' $_ }
    if (-not $State.FirewallOn) { Enable-Firewall }
}
function Invoke-Cleanup {
    if ($DryRun) { return }
    Invoke-Step 'clear PS history' {
        Clear-History
        if (Get-Command Get-PSReadLineOption -ErrorAction SilentlyContinue) { Remove-Item (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue }
    }
    if ($PSCommandPath) { Invoke-Step "delete $PSCommandPath" { Remove-Item -LiteralPath $PSCommandPath -Force } }
}

function Write-Summary {
    $color = @{ OK = 'Green'; FAILED = 'Red'; SKIPPED = 'DarkYellow'; 'DRY RUN' = 'Cyan' }
    $list = { param($a) if (@($a).Count) { @($a) -join ', ' } else { 'none' } }
    Write-Host "`n==== HPCC4 $env:COMPUTERNAME - $([int]((Get-Date) - $Start).TotalSeconds)s ===="
    foreach ($p in $State.Phases) {
        $r = if ($p.Failed.Count) { 'FAILED' } elseif ($p.Skip) { 'SKIPPED' } elseif ($p.Would.Count) { 'DRY RUN' } else { 'OK' }
        Write-Host ('{0,-8} {1}{2}' -f $r, $p.Name, $(if ($p.Skip) { " - $($p.Skip)" })) -ForegroundColor $color[$r]
        @($p.Failed) + @($p.Would) | ForEach-Object { Write-Host "           $_" }
    }
    if ($Unlock) { return }
    $notChanged = @($State.PwTargets | Where-Object { $State.Changed -notcontains $_ })
    Write-Host ''
    Write-Host "Inbound open:      TCP $(& $list (@(Get-KeepPorts) + @($AllowTcp) | Select-Object -Unique))$(if (@($AllowUdp).Count) { " | UDP $(& $list $AllowUdp)" })"
    Write-Host "Outbound kept:     $(& $list $State.OutKept)"
    Write-Host "Deleted:           $(& $list $State.Deleted)"
    Write-Host "Disabled:          $(& $list $State.Disabled)"
    Write-Host "RDP-only (no admin): $(& $list $State.RdpOnly)"
    Write-Host "Password changed:  $(& $list $State.Changed)"
    if ($State.Changed.Count) { Write-Host '                   ^ update these in NEIGH (Users tab) for every check on this box' -ForegroundColor Yellow }
    if (-not $DryRun -and $State.Changed.Count -and $notChanged.Count) { Write-Host "Password NOT set:  $(& $list $notChanged)" -ForegroundColor Red }
    Write-Host "Built-in admin:    $((Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -like '*-500' }).Name)"
    $sus = @($State.Persistence | Where-Object { $_.Suspicious })
    Write-Host "Persistence:       $($State.Persistence.Count) entries, $($sus.Count) suspicious (full list: $OutDir\persistence.txt)"
    $sus | ForEach-Object { Write-Host "  $($_.Type): $($_.Name) -> $($_.Command)" -ForegroundColor Yellow }
}

$build = (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
if ("$build" -ne "$ExpectedBuild") { Write-Host "This script is for OS build $ExpectedBuild, but this box is build $build. Wrong folder for this box? Nothing changed." -ForegroundColor Red; exit 1 }
Invoke-Phase 'Setup' { Initialize-Setup }
if ($Unlock) { Invoke-Phase 'Unlock files' { Unlock-Paths }; Write-Summary; return }
Invoke-Phase 'Backup' { Backup-Targets }
$done = $false
try {
    Invoke-Phase 'Inbound firewall lockdown' { Set-FirewallLockdown }
    Invoke-Phase 'Outbound firewall lockdown' { Set-OutboundLockdown }
    Invoke-Phase 'Delete unauthorized accounts' { Remove-UnauthorizedUsers }
    Invoke-Phase 'Disable accounts' { Disable-Accounts }
    Invoke-Phase 'RDP-only users' { Set-RdpOnlyUsers }
    Invoke-Phase 'Change passwords' { Set-LocalPasswords }
    Invoke-Phase 'Antivirus installer' { Start-AvInstaller }
    Invoke-Phase 'RDP NLA' { Set-RdpNla }
    Invoke-Phase 'Disable services' { Disable-ExtraServices }
    Invoke-Phase 'Persistence report' { Get-PersistenceReport }
    Invoke-Phase 'Install tools' { Install-Tools }
    Invoke-Phase 'STIG GPO' { Install-DodGpo }
    Invoke-Phase 'Lock files' { Lock-Paths }
    $done = $true
} finally {
    Invoke-Phase 'Open scored ports' { Open-ServicePorts }
    if ($State.AvLaunched) { $null = Read-Host 'Scored ports are open. Finish the 360TS install, then press Enter to close outbound 80/443' }
    Invoke-Phase 'Close run-time outbound' { Close-RunOutbound }
    if ($done) { Invoke-Phase 'Cleanup' { Invoke-Cleanup } }
    Write-Summary
}
