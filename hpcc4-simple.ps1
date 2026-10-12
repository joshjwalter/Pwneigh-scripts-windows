# HPCC4 defensive helper: backup, firewall, unauthorized-account removal, local passwords, tools, ACL lock.
# HPCC4-SIMPLE-SCRIPT v1 - stable identity marker; keep this exact line if you rename or copy this file (reset-hpcc4.ps1 and the pre-edit hook key off it, not the filename).
# Every change runs through Invoke-Step, so one failure never stops the rest. Windows PowerShell 5.1, Server 2012 R2 (with WMF 5.1)-2025.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', 'Write-Log', Justification = 'Defined in this script')]
param([switch]$DryRun, [switch]$Unlock, [switch]$Cleanup)
# ---- Tunables (nothing else in this script is hardcoded) ----
$KeepOpenTcp    = @(22)        # open for the WHOLE run, along with the live RDP port (22 = SSH, just in case)
$AllowTcp       = @(3389)      # scored-service TCP ports; opened at the END of the run
$AllowUdp       = @()          # scored-service UDP ports, e.g. 53 for DNS; opened at the END of the run
$BlockTcp       = @()          # inbound TCP to block, e.g. 21, 23
$BlockUdp       = @()          # inbound UDP to block
# Outbound is default-BLOCK: every other local outbound rule is removed. Replies to inbound connections (RDP, SSH, scored
# services) always work - the firewall is stateful - so list only what THIS box starts: DNS lookups, downloads, web -> DB.
$AllowOutTcp    = @(53, 80, 443)  # remote TCP ports this box may connect to (80/443: the tools zip download + Defender signature updates)
$AllowOutUdp    = @(53, 123)      # remote UDP ports (53 = DNS, 123 = NTP time sync)
$AllowOutHosts  = @()          # IPs/subnets this box may reach on ANY port, e.g. '10.0.0.5' (DB server). A domain member's DCs are added automatically
$ExcludeUsers   = @()          # never change these passwords (and never delete these accounts)
$AuthorizedUsers = @()         # local accounts from the packet. Every OTHER non-built-in local account is DELETED ('@()' = skip deleting)
$ToolsDir       = 'C:\Tools'
$ToolsZip       = ''           # local path OR https URL to your tools .zip (files at the zip's root)
$ToolsZipSha256 = ''           # if set, reject a zip whose SHA256 doesn't match
$InstallSysmon  = $false       # true = install/update Sysmon if Sysmon64.exe and sysmonconfig.xml are in the zip
$BackupPaths    = @('C:\Windows\System32\drivers\etc\hosts')
$LockPaths      = @('C:\Windows\System32\drivers\etc\hosts')
$OutDir         = 'C:\HPCC4'   # backups, firewall backup, saved ACLs for -Unlock (no logs: output goes to the terminal only)
# ---- Extra services (the STIG GPO owns the standard service baseline - use this only for extras the packet names) ----
$DisableServices = @()         # extra services to stop + disable, e.g. 'RemoteRegistry', 'TlntSvr', 'SNMP'
# ---- DoD STIG GPO (the bundle from build-gpo-bundle.ps1: LGPO.exe + GPO\ at the tools zip's root, so in $ToolsDir) ----
$ApplyStigGpo      = $true     # apply the OS baseline matching this box (Server 2012 R2 / 2022 / 2025 member server)
$ApplyDefenderStig = $true     # apply the Defender STIG (skipped by itself if Defender isn't installed, e.g. 2012 R2)
$State = @{ Domain = ''; RdpPort = 3389; BackupDir = ''; Purge = $false; Enable = $true; FirewallOn = $false; OutboundBlocked = $false; RulesAdded = @(); Deleted = @(); Changed = @(); ServicesDisabled = @(); Persistence = @(); GpoApplied = @(); GpoBaseline = ''; ToolsInstalled = $false; HashChecked = 'no'; Locked = @(); Failures = @() }

# ---- Helpers ----
function Write-Log { param([string]$Message); Write-Host "$(Get-Date -Format 'HH:mm:ss') $Message" }   # terminal only; nothing is written to disk
# Runs one change. -DryRun: log WOULD and run nothing. Fails on an exception, a cmdlet error, or a native exit code
# (robocopy: 8+ fails, 0-7 is success; everything else: non-zero fails). Logs DONE or FAILED, returns $true/$false, never
# throws. Shared by reset-hpcc4.ps1 (dot-sourced), so both scripts get live confirmation of every successful step.
function Invoke-Step {
    param([Parameter(Position = 0)][string]$Name, [Parameter(Position = 1)][scriptblock]$Action, [switch]$RobocopyCodes)
    if ($DryRun) { Write-Log "WOULD: $Name"; return $false }
    $global:LASTEXITCODE = 0
    try {
        $out = & $Action 2>&1
        $errs = @($out | Where-Object { $_ -is [Management.Automation.ErrorRecord] -and $_.FullyQualifiedErrorId -notlike 'NativeCommandError*' })
        $failed = if ($RobocopyCodes) { $LASTEXITCODE -ge 8 } else { $LASTEXITCODE -ne 0 }
        if (-not $failed -and $errs.Count -eq 0) { Write-Log "DONE: $Name"; return $true }
        Write-Log "FAILED: ${Name}: exit $LASTEXITCODE $(if ($errs.Count) { $errs[0] } else { ($out | Select-Object -Last 1) -join ' ' })"
    } catch { Write-Log "FAILED: ${Name}: $($_.Exception.Message)" }
    $State.Failures += $Name; return $false
}
function Test-IsAdmin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }   # used by reset-hpcc4.ps1
# Restricts a folder to Administrators + SYSTEM full control (plus any extra grant), removing inherited permissions.
# Shared by Initialize-Setup ($OutDir) and Install-Tools ($ToolsDir) so the lockdown ACL is defined in exactly one place.
function Lock-AdminOnlyAcl {
    param([string]$Path, [string[]]$ExtraGrants = @())
    icacls $Path /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' @ExtraGrants
}

# ---- Accounts ----
function Get-LocalEnabledUsers { (Get-LocalUser | Where-Object Enabled).Name }
# Every enabled local account except $ExcludeUsers. Service, app-pool and task accounts are NOT protected.
function Get-PasswordTargets { @(Get-LocalEnabledUsers) | Where-Object { @($ExcludeUsers) -notcontains $_ } }

# ---- Firewall ----
function Get-ListeningPorts {
    $proc = @{ n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } }
    @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object @{ n = 'Proto'; e = { 'TCP' } }, @{ n = 'Port'; e = { [int]$_.LocalPort } }, $proc) +
    @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object @{ n = 'Proto'; e = { 'UDP' } }, @{ n = 'Port'; e = { [int]$_.LocalPort } }, $proc) | Sort-Object Proto, Port -Unique
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
# Removes every local outbound rule except Core Networking (DNS client, DHCP, IPv6 neighbor discovery) and $Keep.
function Remove-OutboundRules {
    param([string[]]$Keep)
    $names = @(Get-NetFirewallRule -Direction Outbound -PolicyStore PersistentStore -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } |
        Where-Object { $Keep -notcontains $_ -and $_ -notlike 'CoreNet-*' })
    if ($names.Count) { Invoke-Step "remove $($names.Count) outbound firewall rules" { Remove-NetFirewallRule -Name $names } }
}
# $AllowOutHosts plus, on a domain member, its DCs (the domain name's A records), so domain logons and GPO keep working.
function Get-OutboundAllowHosts {
    $dcs = @()
    if ($State.Domain) {
        $dcs = @(Resolve-DnsName -Name $State.Domain -Type A -DnsOnly -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress } | Where-Object { $_ })
        if ($dcs.Count) { Write-Log "Domain member of $($State.Domain): allowing outbound to its DCs $($dcs -join ', ')" }
    }
    @(@($AllowOutHosts) + $dcs | Where-Object { $_ } | Select-Object -Unique)
}

# ---- Steps, in run order ----
function Initialize-Setup {
    $rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction SilentlyContinue).PortNumber
    $State.RdpPort = if ($rdp) { [int]$rdp } else { 3389 }
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $State.Domain = if ($cs.PartOfDomain) { $cs.Domain } else { '' }   # member servers need outbound to their DCs
    Invoke-Step 'create OutDir' { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
    Invoke-Step 'lock down OutDir' { Lock-AdminOnlyAcl $OutDir }
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
    $State.Purge = $true
    # Add the keep rules BEFORE removing anything, so RDP never has a gap. Keep rules that already exist are left alone.
    Get-KeepPorts | Where-Object { -not (Get-NetFirewallRule -Name "HPCC4-Keep-TCP-$_" -ErrorAction SilentlyContinue) } | ForEach-Object { Add-Rule 'Keep' 'TCP' $_ }
    Remove-InboundRules -All
    Enable-Firewall -BlockInbound
}
# Right after the inbound lockdown: allow only $AllowOutTcp/$AllowOutUdp/$AllowOutHosts (+ a member's DCs), remove every
# other local outbound rule except Core Networking, then block outbound by default. Cuts reverse shells and C2 callbacks.
function Set-OutboundLockdown {
    $hosts = @(Get-OutboundAllowHosts)
    $rules = [ordered]@{}
    @($AllowOutTcp) | ForEach-Object { $rules["HPCC4-Out-TCP-$_"] = @{ Protocol = 'TCP'; RemotePort = $_ } }
    @($AllowOutUdp) | ForEach-Object { $rules["HPCC4-Out-UDP-$_"] = @{ Protocol = 'UDP'; RemotePort = $_ } }
    $hosts | ForEach-Object { $rules["HPCC4-Out-Host-$($_ -replace '/', '_')"] = @{ RemoteAddress = $_ } }
    # Add the allow rules BEFORE removing anything or blocking. Ones that already exist are left alone; stale HPCC4-Out-* go.
    # Each match is a remote Protocol + RemotePort, or a RemoteAddress on any port.
    foreach ($n in @($rules.Keys)) {
        $match = $rules[$n]
        if (-not (Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue) -and (Invoke-Step $n { New-NetFirewallRule -Name $n -DisplayName $n -Direction Outbound -Action Allow @match })) { $State.RulesAdded += $n }
    }
    Remove-OutboundRules @($rules.Keys)
    $State.OutboundBlocked = Invoke-Step 'block outbound by default' { Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultOutboundAction Block }
}
# Deletes every non-built-in local account (ID >= 1000) not in $AuthorizedUsers or $ExcludeUsers. No prompt, and that
# includes YOUR account and service/app-pool/task accounts if they aren't listed. Deleting can't be undone.
function Remove-UnauthorizedUsers {
    if (-not $AuthorizedUsers) { Write-Log 'Skipping account removal: $AuthorizedUsers is empty.'; return }
    $keep = @(@($AuthorizedUsers) + @($ExcludeUsers))
    foreach ($u in @(Get-LocalUser | Where-Object { [int]($_.SID.Value -split '-')[-1] -ge 1000 -and $keep -notcontains $_.Name })) {
        if (Invoke-Step "delete account $($u.Name) (SID $($u.SID.Value))" { Remove-LocalUser -SID $u.SID }) { $State.Deleted += $u.Name }
    }
}
function Set-LocalPasswords {
    $targets = @(Get-PasswordTargets); Write-Log "Password targets: $($targets -join ', ')"
    if ($DryRun) { Write-Log 'WOULD: change passwords for targets above'; return }
    # Entered once, not confirmed: a typo sets that typo on every target. Never logged, echoed or put on a command line.
    $pw = Read-Host 'New password (blank to skip)' -AsSecureString; if ($pw.Length -eq 0) { return }
    foreach ($u in $targets) { if (Invoke-Step "password $u" { Set-LocalUser -Name $u -Password $pw }) { $State.Changed += $u } }
    $pw = $null
    Write-Log "Changed accounts: $($State.Changed -join ', ')"; Write-Log 'SUBMIT PASSWORD CHANGES TO THE SCOREBOARD.'
}
# RDP Network Level Authentication: no GPO in the DISA package sets it, so the script does. RDP clients must log in
# before a session (and its login screen) exists. Sessions already connected stay up.
function Set-RdpNla {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    if ((Get-ItemProperty $key -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication -eq 1) { Write-Log 'RDP NLA already on.' }
    else { Invoke-Step 'RDP NLA on' { Set-ItemProperty $key -Name UserAuthentication -Value 1 -Type DWord } }
}
# ---- Extra services ----
# Stops + disables only the services in $DisableServices (extras beyond the STIG GPO's baseline). Empty by default = no-op.
function Disable-ExtraServices {
    foreach ($svc in @($DisableServices)) {
        if (-not (Get-Service -Name $svc -ErrorAction SilentlyContinue)) { Write-Log "service skip (not present): $svc"; continue }
        if (Invoke-Step "stop + disable service $svc" { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue; Set-Service -Name $svc -StartupType Disabled }) { $State.ServicesDisabled += $svc }
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
    @{ Type = 'AppInit/AppCert'; Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; Values = 'AppInit_DLLs', 'AppCertDLLs' },
    @{ Type = 'LSA-Package'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Values = 'Security Packages', 'Notification Packages', 'Authentication Packages' }
)
$script:PsSyntheticProps = 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider'
# Lists everything in $PersistenceRegistrySources, IFEO debugger hijacks, Active Setup StubPath, EVERY scheduled task
# (including under \Microsoft\*, where masquerading persistence hides), off-path auto services (including svchost
# ServiceDll hijacks), WMI subscriptions, every local user's Startup folder, and any currently logged-on OTHER user's
# Run/RunOnce (via their already-loaded hive under HKEY_USERS - nothing is mounted or unmounted by this script).
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
    $sus = @($found | Where-Object { $_.Suspicious })
    Write-Log "Persistence: $($found.Count) autostart entries found, $($sus.Count) flagged SUSPICIOUS - review, nothing was removed."
    foreach ($s in $sus) { Write-Log "  SUSPICIOUS $($s.Type): $($s.Name) -> $($s.Command)" }
    $report = Join-Path $OutDir 'persistence.txt'
    Invoke-Step "write persistence report ($report)" { $found | Format-Table -AutoSize | Out-String -Width 4096 | Set-Content -Path $report }
}
# ---- DoD STIG GPO ----
# The bundle's OS baselines are member-server ones: right for a standalone or member server, wrong for a DC or a workstation.
# Returns the bundle folder for this box (ProductType 3 = server, by build number), or $null with a warning.
function Get-StigGpoFolder {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $map = @{ '9600' = 'Server2012R2'; '20348' = 'Server2022'; '26100' = 'Server2025' }
    if ("$($os.ProductType)" -eq '3' -and $map.ContainsKey("$($os.BuildNumber)")) { return $map["$($os.BuildNumber)"] }
    Write-Log "WARNING: no STIG baseline for $($os.Caption) (build $($os.BuildNumber), product type $($os.ProductType)) - the bundle only has member-server baselines for 2012 R2, 2022 and 2025. OS GPO skipped."
}
# Saves the local policy once, before the first GPO apply (LGPO backup, security template, audit policy), so it always
# holds the original. reset-hpcc4.ps1 restores from it. A partial backup is deleted so the next run retries it whole.
function Backup-LocalPolicy {
    param([string]$Lgpo)
    $dir = Join-Path $OutDir 'gpo-before'
    if (Test-Path $dir) { Write-Log 'gpo-before exists, keeping the original'; return $true }
    $ok = @(
        Invoke-Step 'backup local policy (LGPO)' { New-Item -ItemType Directory -Path $dir | Out-Null; & $Lgpo /b $dir /n 'gpo-before' }
        Invoke-Step 'backup security policy' { secedit /export /cfg (Join-Path $dir 'secpol-before.inf') /quiet }
        Invoke-Step 'backup audit policy' { auditpol /backup "/file:$(Join-Path $dir 'audit-before.csv')" }
    ) -notcontains $false
    if (-not $ok -and -not $DryRun) { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    $ok
}
# Applies this box's OS baseline (+ the Defender STIG) from the GPO bundle with LGPO.exe, then gpupdate. Runs after the
# firewall and password steps, and after Install-Tools unpacks LGPO.exe + GPO\. Open-ServicePorts re-asserts our rules at the end.
function Install-DodGpo {
    $dir = Join-Path $ToolsDir 'GPO'; $lgpo = Join-Path $ToolsDir 'LGPO.exe'
    if (-not (Test-Path $dir)) { Write-Log "GPO bundle not found: $dir - STIG GPO not applied."; return }
    $folders = @()
    if ($ApplyStigGpo) { $os = Get-StigGpoFolder; if ($os) { $folders += $os } }
    if ($ApplyDefenderStig -and (Get-Service -Name WinDefend -ErrorAction SilentlyContinue)) { $folders += 'Defender' }
    # A GPO backup folder is any folder that holds a Backup.xml (the GUID-named subfolders in the bundle).
    $backups = @(foreach ($f in $folders) { Get-ChildItem -Path (Join-Path $dir $f) -Recurse -Filter 'Backup.xml' -ErrorAction SilentlyContinue | ForEach-Object { $_.Directory.FullName } })
    if (-not $backups.Count) { return }
    $null = Backup-LocalPolicy $lgpo   # applies even if this backup fails
    $State.GpoBaseline = $folders -join ' + '
    foreach ($b in $backups) { if (Invoke-Step "LGPO apply $(Split-Path $b -Leaf)" { & $lgpo /g $b }) { $State.GpoApplied += $b } }
    Invoke-Step 'gpupdate /force' { gpupdate /force }
    # The bundle names the renamed admin account: don't leave it for a red teamer.
    Invoke-Step "delete GPO bundle $dir" { Remove-Item $dir -Recurse -Force }
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
    if (-not $ToolsZip) { Write-Log 'No tools zip set; skipping tools.'; return }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12   # GitHub needs TLS 1.2
    $ProgressPreference = 'SilentlyContinue'   # PowerShell 5.1 downloads are many times slower with the progress bar on
    # Lock ToolsDir BEFORE anything goes in, so every file inherits "only admins can write" and nobody can plant a fake tool.
    Invoke-Step 'create ToolsDir' { New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null }
    Invoke-Step 'lock down ToolsDir' { Lock-AdminOnlyAcl $ToolsDir @('*S-1-5-32-545:(OI)(CI)RX') }
    Expand-ToolsZip
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
# True only if Everyone is specifically denied the Write right this script's own Lock-Paths applies - not just any
# unrelated pre-existing Deny-Everyone ACE (e.g. a Deny-Read from some other policy), which would give a false "already locked".
function Test-EveryoneDeny {
    param([string]$Path)
    try {
        [bool]((Get-Acl $Path).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Value -eq 'S-1-1-0' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write)
        })
    } catch { $false }
}
# Lock: save the original ACL once, set read-only, then deny Everyone write/delete. WRITE_DAC isn't denied, so the lock can always be undone.
function Lock-Paths {
    foreach ($path in $LockPaths) {
        $item = Get-Item $path -ErrorAction SilentlyContinue; if (-not $item) { Write-Log "lock skip (missing): $path"; continue }
        $save = Get-AclSaveFile $path; $isDir = $item.PSIsContainer
        # Never overwrite a save (a 2nd run would save the LOCKED ACL). The lock goes on even if the save fails.
        if (-not (Test-Path $save)) { Invoke-Step "save ACL $path" { if ($isDir) { icacls $path /save $save /T } else { icacls $path /save $save }; Set-Content ([IO.Path]::ChangeExtension($save, '.path')) $path } }
        Invoke-Step "attrib +R $path" { attrib +R $path }   # before the deny, which blocks attribute changes
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
    # Windows block rules beat allow rules: a port in both $BlockTcp and $AllowTcp (or the RDP port) ends up BLOCKED.
    @($BlockTcp) | ForEach-Object { Add-Rule 'Block' 'TCP' $_ }
    @($BlockUdp) | ForEach-Object { Add-Rule 'Block' 'UDP' $_ }
    if ($State.Enable -and -not $State.FirewallOn) { Enable-Firewall }
}
function Write-Summary {
    Write-Log "Backup: $($State.BackupDir) | Old inbound rules removed: $($State.Purge) | Firewall on: $($State.FirewallOn) | Outbound blocked: $($State.OutboundBlocked)"
    Write-Log "Rules added: $($State.RulesAdded -join ', ') | Accounts deleted: $($State.Deleted -join ', ') | Passwords changed: $($State.Changed -join ', ')"
    Write-Log "Extra services disabled: $($State.ServicesDisabled -join ', ')"
    Write-Log "Persistence entries: $($State.Persistence.Count) ($(@($State.Persistence | Where-Object { $_.Suspicious }).Count) suspicious) | DoD GPOs applied: $($State.GpoApplied.Count) ($($State.GpoBaseline))"
    Write-Log "Tools installed: $($State.ToolsInstalled) | Hash check: $($State.HashChecked) | Locked: $($State.Locked -join ', ') | Failures: $($State.Failures -join ', ')"
}
# Clears PS history and every Windows event log, then deletes this script file - and its folder only if that leaves it
# empty. Never a whole folder: run from the Desktop or Downloads, that would wipe it, and $OutDir's backups and ACL saves
# (which -Unlock needs) must survive. PowerShell reads a script fully before running it, so it can delete its own file.
# -ScriptPath exists for the tests; a run from a pasted/compiled build has no file, so there is nothing to delete.
function Invoke-Cleanup {
    param([string]$ScriptPath = $PSCommandPath)
    if ($DryRun) { Write-Log 'WOULD: clear PS history, clear event logs, delete this script'; return }
    Invoke-Step 'clear PS history' {
        Clear-History
        if (Get-Command Get-PSReadLineOption -ErrorAction SilentlyContinue) { Remove-Item (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue }
    }
    Invoke-Step 'clear event logs' {
        Get-WinEvent -ListLog * | ForEach-Object {
            try { [Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) } catch {}
        }
    }
    if (-not $ScriptPath) { Write-Log 'Not running from a script file - nothing to self-delete.'; return }
    if (-not (Invoke-Step "delete $ScriptPath" { Remove-Item -LiteralPath $ScriptPath -Force })) { return }
    $dir = Split-Path $ScriptPath -Parent
    $left = @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)
    if ($left.Count) { Write-Log "Left $dir in place - it still holds: $(($left | Select-Object -First 5).Name -join ', ')$(if ($left.Count -gt 5) { ', ...' }). Delete what you don't need by hand." }
    else { Invoke-Step "delete empty folder $dir (fails if it's your shell's current folder - cd out and delete it)" { Remove-Item -LiteralPath $dir -Force } }
}
function Main {
    $null = Initialize-Setup   # $null = hides Invoke-Step's True/False results from the console
    if ($Unlock) { $null = Unlock-Paths; return }
    $null = Backup-Targets
    # finally: the service ports reopen even if a step fails or you press Ctrl+C, so services never stay closed.
    # Firewall and passwords first (they kick red team out); the GPO after Install-Tools, which unpacks LGPO.exe and GPO\.
    try { $null = Set-FirewallLockdown; $null = Set-OutboundLockdown; $null = Remove-UnauthorizedUsers; $null = Set-LocalPasswords; $null = Set-RdpNla; $null = Disable-ExtraServices; $null = Get-PersistenceReport; $null = Install-Tools; $null = Install-DodGpo; $null = Lock-Paths }
    finally { $null = Open-ServicePorts; Write-Summary }
    if ($Cleanup) { $null = Invoke-Cleanup }
}
if ($MyInvocation.InvocationName -ne '.') { Main }
