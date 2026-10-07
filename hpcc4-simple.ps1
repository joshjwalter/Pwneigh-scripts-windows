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
$State = @{ IsDC = $false; Domain = ''; RdpPort = 3389; BackupDir = ''; Uncovered = @(); Purge = $false; Enable = $true; FirewallOn = $false; OutboundBlocked = $false; RulesAdded = @(); BlocksRefused = @(); Deleted = @(); Changed = @(); ServicesDisabled = @(); Persistence = @(); GpoApplied = @(); GpoBaseline = ''; ToolsInstalled = $false; HashChecked = 'no'; Locked = @(); Failures = @() }

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
function Test-IsAdmin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
function ConvertFrom-SecureText { param([Security.SecureString]$Secure); $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure); try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) } }
# Restricts a folder to Administrators + SYSTEM full control (plus any extra grant), removing inherited permissions.
# Shared by Initialize-Setup ($OutDir) and Install-Tools ($ToolsDir) so the lockdown ACL is defined in exactly one place.
function Lock-AdminOnlyAcl {
    param([string]$Path, [string[]]$ExtraGrants = @())
    icacls $Path /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' @ExtraGrants
}

# ---- Accounts ----
function Get-LocalEnabledUsers { (Get-LocalUser | Where-Object Enabled).Name }
# Accounts that services, IIS app pools and scheduled tasks run as. Changing their passwords would break them.
function Get-InUseAccounts {
    (Get-CimInstance -ClassName Win32_Service).StartName
    $appcmd = "$env:windir\system32\inetsrv\appcmd.exe"; if (Test-Path $appcmd) { & $appcmd list apppool /text:processModel.userName }
    (Get-ScheduledTask).Principal.UserId
}
# Names that must never be deleted or password-reset: you, $ExcludeUsers, and accounts services/tasks run as. Re-queries
# Get-InUseAccounts fresh on every call (deliberately NOT cached): Set-FirewallLockdown's uncovered-ports prompt and the
# delete/password confirmation prompts below can each block on the operator for an arbitrary time, and a stale snapshot
# taken before those prompts could let a newly-in-use account get deleted or password-reset by the time this runs.
# '.\bob', 'HOST\bob' and 'CORP\bob' all normalize to 'bob'; -contains/-notcontains below are case-insensitive.
# Shared by Get-PasswordTargets and Remove-UnauthorizedUsers so both protect exactly the same accounts.
function Get-ProtectedAccountNames {
    @($ExcludeUsers) + @(Get-InUseAccounts) + $env:USERNAME | Where-Object { $_ } | ForEach-Object { $_ -replace '^.*\\' } | Select-Object -Unique
}
function Get-PasswordTargets {
    $skip = @(Get-ProtectedAccountNames)
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
# Live outbound TCP connections the lockdown would cut: not loopback, not an inbound session on one of our listening ports
# (RDP, SSH, a scored service), not to an allowed port or host. Exact host IPs only (subnets aren't expanded): it may
# over-warn, never under-warn. Each one is a scored dependency you forgot (web -> DB) or something that shouldn't be there.
function Get-UncoveredOutbound {
    param([string[]]$AllowHosts)
    $listen = @(Get-ListeningPorts | Where-Object { $_.Proto -eq 'TCP' } | ForEach-Object { $_.Port })
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
        $_.RemoteAddress -notmatch '^(::ffff:)?127\.|^::1$' -and $listen -notcontains [int]$_.LocalPort -and
        @($AllowOutTcp) -notcontains [int]$_.RemotePort -and @($AllowHosts) -notcontains $_.RemoteAddress
    } | Select-Object @{ n = 'Remote'; e = { "$($_.RemoteAddress):$($_.RemotePort)" } }, @{ n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } } |
        Sort-Object Remote -Unique
}

# ---- Steps, in run order ----
function Initialize-Setup {
    $rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction SilentlyContinue).PortNumber
    $State.RdpPort = if ($rdp) { [int]$rdp } else { 3389 }
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $State.IsDC = $cs.DomainRole -in 4, 5
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
# Purging old rules and switching to default-block are separate decisions: skipping one for safety doesn't require skipping the other.
function Set-FirewallLockdown {
    $keep = Get-KeepPorts; $State.Enable = $true; $State.Purge = $true; $block = $true
    if ($State.IsDC) {
        $State.Purge = $false; $block = $false
        Write-Log 'WARNING: domain controller - NOT removing existing firewall rules and NOT switching to default-block (AD needs dynamic RPC ports).'
    } elseif (-not $DryRun -and -not (Test-Path (Join-Path $OutDir 'firewall-before.wfw'))) {
        $State.Purge = $false
        Write-Log 'WARNING: no firewall backup (firewall-before.wfw) - NOT removing existing firewall rules. Still switching to default-block.'
    }
    # Warn about listening ports that nothing will allow. Without a purge, existing allow rules still count.
    $covered = @(@($AllowTcp) + $keep | ForEach-Object { "TCP:$_" }) + @(@($AllowUdp) | ForEach-Object { "UDP:$_" })
    if (-not $State.Purge) { $covered += @(Get-InboundAllowPorts) }
    $State.Uncovered = @(Get-ListeningPorts | Where-Object { $covered -notcontains "$($_.Proto):$($_.Port)" })
    $State.Uncovered | ForEach-Object { Write-Log "WARNING: $($_.Proto) $($_.Port) ($($_.Process)) is listening but not covered - this service will be blocked once the firewall is on." }
    if ($State.Uncovered.Count -and -not $DryRun -and (Read-Host 'Uncovered ports found. Lock down the firewall anyway? y/N') -ne 'y') {
        $State.Enable = $false; $State.Purge = $false; $block = $false; Write-Log 'Firewall left as it is; HPCC4 rules will still be added at the end.'
    }
    # Add the keep rules BEFORE removing anything, so RDP never has a gap. Keep rules that already exist are left alone.
    $keep | Where-Object { -not (Get-NetFirewallRule -Name "HPCC4-Keep-TCP-$_" -ErrorAction SilentlyContinue) } | ForEach-Object { Add-Rule 'Keep' 'TCP' $_ }
    if ($State.Purge) { Remove-InboundRules -All }
    if ($block) { Enable-Firewall -BlockInbound }
}
# Right after the inbound lockdown: allow only $AllowOutTcp/$AllowOutUdp/$AllowOutHosts (+ a member's DCs), remove every
# other local outbound rule except Core Networking, then block outbound by default. Cuts reverse shells and C2 callbacks.
function Set-OutboundLockdown {
    if ($State.IsDC) { Write-Log 'WARNING: domain controller - NOT locking down outbound (replication and AD clients need it).'; return }
    if (-not $State.Enable) { Write-Log 'Outbound left as it is: the inbound lockdown was declined.'; return }
    if (-not $DryRun -and -not (Test-Path (Join-Path $OutDir 'firewall-before.wfw'))) { Write-Log 'WARNING: no firewall backup (firewall-before.wfw) - NOT locking down outbound.'; return }
    $hosts = @(Get-OutboundAllowHosts)
    if ($State.Domain -and -not $hosts.Count) { Write-Log "WARNING: domain member of $($State.Domain) but no DC found and `$AllowOutHosts is empty - NOT locking down outbound (domain logons could break). Put the DC's IP in `$AllowOutHosts."; return }
    $cut = @(Get-UncoveredOutbound $hosts)
    $cut | ForEach-Object { Write-Log "WARNING: outbound connection to $($_.Remote) ($($_.Process)) is not allowed and will be cut. Scored dependency? Add it to `$AllowOutTcp or `$AllowOutHosts." }
    if ($cut.Count -and -not $DryRun -and (Read-Host 'Uncovered outbound connections found. Block outbound anyway? y/N') -ne 'y') { Write-Log 'Outbound left as it is.'; return }
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
# Deletes local accounts that aren't authorized. Always kept: built-ins (ID < 1000: Administrator even if renamed, Guest, etc.),
# you, $AuthorizedUsers, $ExcludeUsers, and accounts that services, app pools or tasks run as. Deleting can't be undone,
# so each account's SID and groups are printed first, in case you need to recreate it.
function Remove-UnauthorizedUsers {
    if ($State.IsDC) { Write-Log 'Skipping account removal: this is a domain controller.'; return }
    if (-not $AuthorizedUsers) { Write-Log 'Skipping account removal: $AuthorizedUsers is empty.'; return }
    $keep = @(@($AuthorizedUsers) + @(Get-ProtectedAccountNames))
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
    if (-not $ApplyStigGpo -and -not $ApplyDefenderStig) { Write-Log 'WARNING: $ApplyStigGpo and $ApplyDefenderStig are both off - no STIG GPO applied.'; return }
    $dir = Join-Path $ToolsDir 'GPO'; $lgpo = Join-Path $ToolsDir 'LGPO.exe'
    if (-not (Test-Path $dir)) { Write-Log "WARNING: GPO bundle not found: $dir (deleted after an earlier successful apply?) - STIG GPO NOT applied this run."; return }
    if (-not (Test-Path $lgpo)) { Write-Log "WARNING: LGPO.exe not found ($lgpo). Put it in the tools zip. STIG GPO NOT applied."; return }
    $folders = @()
    if ($ApplyStigGpo) { $os = Get-StigGpoFolder; if ($os) { $folders += $os } }
    if ($ApplyDefenderStig) {
        if (Get-Service -Name WinDefend -ErrorAction SilentlyContinue) { $folders += 'Defender' }
        else { Write-Log 'WARNING: Microsoft Defender (WinDefend) is not installed - Defender STIG skipped. This box needs another AV.' }
    }
    # A GPO backup folder is any folder that holds a Backup.xml (the GUID-named subfolders in the bundle).
    $backups = @(foreach ($f in $folders) { Get-ChildItem -Path (Join-Path $dir $f) -Recurse -Filter 'Backup.xml' -ErrorAction SilentlyContinue | ForEach-Object { $_.Directory.FullName } })
    if (-not $backups.Count) { Write-Log "WARNING: no GPO backups found for '$($folders -join ', ')' under $dir - STIG GPO NOT applied."; return }
    if (-not (Backup-LocalPolicy $lgpo) -and -not $DryRun) { Write-Log 'WARNING: local policy backup failed - STIG GPO NOT applied (there would be nothing to roll back to).'; return }
    $State.GpoBaseline = $folders -join ' + '
    Write-Log "Applying $($State.GpoBaseline): $($backups.Count) GPO backup(s) with LGPO."
    foreach ($b in $backups) { if (Invoke-Step "LGPO apply $(Split-Path $b -Leaf)" { & $lgpo /g $b }) { $State.GpoApplied += $b } }
    Invoke-Step 'gpupdate /force' { gpupdate /force }
    # The bundle names the renamed admin account and shows exactly which STIG lines were skipped: don't leave it for a red teamer.
    if ($State.GpoApplied.Count -eq $backups.Count) { Invoke-Step "delete GPO bundle $dir" { Remove-Item $dir -Recurse -Force } }
    if ($DryRun) { return }
    Test-GpoResult
}
# Right after the GPO applies: warn about policy that changes access to THIS box or undoes the script's own work.
function Test-GpoResult {
    $mergeOff = foreach ($prof in 'DomainProfile', 'StandardProfile', 'PrivateProfile', 'PublicProfile') {
        $v = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$prof" -Name AllowLocalPolicyMerge -ErrorAction SilentlyContinue).AllowLocalPolicyMerge
        if ($null -ne $v -and $v -eq 0) { $prof }
    }
    # The DoD firewall STIG REQUIRES outbound default-allow, and policy beats the local profile setting.
    $outAllow = foreach ($prof in 'DomainProfile', 'PrivateProfile', 'PublicProfile') {
        $v = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$prof" -Name DefaultOutboundAction -ErrorAction SilentlyContinue).DefaultOutboundAction
        if ($null -ne $v -and $v -eq 0) { $prof }
    }
    if ($outAllow -and $State.OutboundBlocked) { Write-Log "WARNING: GPO sets DefaultOutboundAction=Allow for $($outAllow -join ', ') - the outbound lockdown is OVERRIDDEN by policy. The bundle should never contain firewall policy - rebuild it. See gpo-verification-checklist.md." }
    if ($mergeOff) { Write-Log "WARNING: GPO sets AllowLocalPolicyMerge=0 for $($mergeOff -join ', ') - local HPCC4-Keep-*/Allow firewall rules are now IGNORED by policy. RDP/SSH may be unreachable even with the rule present. See gpo-verification-checklist.md." }
    if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy' -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1) {
        Write-Log 'WARNING: FIPS mode is ON (the bundle leaves it alone, so it was on already) - old web apps and RDP/SSH clients may fail.'
    }
    $admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
    if ($admin) { Write-Log "Built-in Administrator is now named '$($admin.Name)' - log in with that name from now on." }
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
    if ($State.OutboundBlocked -and @($AllowOutTcp) -notcontains 443) { Write-Log 'WARNING: outbound is blocked and TCP 443 is not in $AllowOutTcp - HTTPS downloads below will fail.' }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12   # GitHub needs TLS 1.2
    $ProgressPreference = 'SilentlyContinue'   # PowerShell 5.1 downloads are many times slower with the progress bar on
    # Lock ToolsDir BEFORE anything goes in, so every file inherits "only admins can write" and nobody can plant a fake tool.
    Invoke-Step 'create ToolsDir' { New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null }
    if (-not (Invoke-Step 'lock down ToolsDir' { Lock-AdminOnlyAcl $ToolsDir @('*S-1-5-32-545:(OI)(CI)RX') }) -and -not $DryRun) { return }
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
    Write-Log "Backup: $($State.BackupDir) | Uncovered ports: $($State.Uncovered.Count) | Old inbound rules removed: $($State.Purge) | Firewall on: $($State.FirewallOn) | Outbound blocked: $($State.OutboundBlocked)"
    Write-Log "Rules added: $($State.RulesAdded -join ', ') | Blocks refused: $($State.BlocksRefused -join ', ') | Accounts deleted: $($State.Deleted -join ', ') | Passwords changed: $($State.Changed -join ', ')"
    Write-Log "Extra services disabled: $($State.ServicesDisabled -join ', ')"
    Write-Log "Persistence entries: $($State.Persistence.Count) ($(@($State.Persistence | Where-Object { $_.Suspicious }).Count) suspicious) | DoD GPOs applied: $($State.GpoApplied.Count) ($($State.GpoBaseline))"
    Write-Log "Tools installed: $($State.ToolsInstalled) | Hash check: $($State.HashChecked) | Locked: $($State.Locked -join ', ') | Failures: $($State.Failures -join ', ')"
    if (-not $State.GpoApplied.Count) { Write-Log 'WARNING: no DoD STIG GPOs were applied this run - the STIG baseline in gpo-verification-checklist.md (WDigest, SMBv1, SMB signing, Guest account, lockout, ...) was NOT applied unless an earlier run or you did it.' }
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
    if (-not (Test-IsAdmin)) { Write-Log 'Must be run elevated (as Administrator). Exiting.'; exit 1 }
    # Server 2012 R2 ships PowerShell 4, which lacks Get-LocalUser and Expand-Archive.
    if ($PSVersionTable.PSVersion.Major -lt 5) { Write-Log "PowerShell $($PSVersionTable.PSVersion) - this script needs 5.1. Install WMF 5.1 (KB3191564 on 2012 R2, needs a reboot), then run it again. Exiting."; exit 1 }
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
