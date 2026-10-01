# HPCC4 defensive helper: backup, firewall, unauthorized-account removal, local passwords, tools, ACL lock.
# HPCC4-SIMPLE-SCRIPT v1 - stable identity marker; keep this exact line if you rename or copy this file (reset-hpcc4.ps1 and the pre-edit hook key off it, not the filename).
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
$AvInstallerExpectedSigner = '' # if set, substring match against the installer's Authenticode signer subject; empty = only validity is checked (current behavior)
$InstallSysmon  = $false       # true = install/update Sysmon if Sysmon64.exe and sysmonconfig.xml are in the zip
$BackupPaths    = @('C:\Windows\System32\drivers\etc\hosts')
$LockPaths      = @('C:\Windows\System32\drivers\etc\hosts')
$OutDir         = 'C:\HPCC4'   # backups, firewall backup, saved ACLs for -Unlock (no logs: output goes to the terminal only)
# ---- Extra services (the STIG GPO owns the standard service baseline - use this only for extras the packet names) ----
$DisableServices = @()         # extra services to stop + disable, e.g. 'RemoteRegistry', 'TlntSvr', 'SNMP'
# ---- DoD STIG GPO (needs LGPO.exe) ----
$DodGpoDir = ''                # folder holding extracted STIG GPO backups (each a subfolder with a Backup.xml). '' = skip
$LgpoExe   = ''                # path to LGPO.exe; '' = look in $ToolsDir
$State = @{ IsDC = $false; RdpPort = 3389; BackupDir = ''; Uncovered = @(); Purge = $false; Enable = $true; FirewallOn = $false; RulesAdded = @(); BlocksRefused = @(); Deleted = @(); Changed = @(); ServicesDisabled = @(); Persistence = @(); GpoApplied = @(); ToolsInstalled = $false; HashChecked = 'no'; AvInstaller = ''; Locked = @(); Failures = @() }

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

# ---- Steps, in run order ----
function Initialize-Setup {
    $rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction SilentlyContinue).PortNumber
    $State.RdpPort = if ($rdp) { [int]$rdp } else { 3389 }
    $State.IsDC = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -in 4, 5
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
# Applies every GPO backup under $DodGpoDir with LGPO.exe, then gpupdate. STIG GPOs are heavy and can break scored services -
# run only after a backup, and re-check RDP/firewall afterward (Open-ServicePorts re-asserts our own rules at the very end).
function Install-DodGpo {
    if (-not $DodGpoDir) { Write-Log 'WARNING: $DodGpoDir not set - skipping DoD STIG GPO. RDP NLA, WDigest, SMBv1, SMB signing and Guest-account hardening from gpo-verification-checklist.md will NOT be applied by this script.'; return }
    if (-not (Test-Path $DodGpoDir)) { Write-Log "WARNING: DoD GPO dir not found: $DodGpoDir - STIG hardening NOT applied."; return }
    $lgpo = if ($LgpoExe) { $LgpoExe } else { Join-Path $ToolsDir 'LGPO.exe' }
    if (-not (Test-Path $lgpo)) { Write-Log "WARNING: LGPO.exe not found ($lgpo). Put it in `$ToolsDir or set `$LgpoExe. STIG hardening NOT applied."; return }
    # A GPO backup folder is any folder that holds a Backup.xml (the GUID-named subfolders inside the STIG package).
    $backups = @(Get-ChildItem -Path $DodGpoDir -Recurse -Filter 'Backup.xml' -ErrorAction SilentlyContinue | ForEach-Object { $_.Directory.FullName } | Sort-Object -Unique)
    if (-not $backups.Count) { Write-Log "WARNING: no GPO backups (Backup.xml) found under $DodGpoDir. STIG hardening NOT applied."; return }
    Write-Log "Applying $($backups.Count) DoD STIG GPO backup(s) with LGPO."
    foreach ($b in $backups) { if (Invoke-Step "LGPO apply $(Split-Path $b -Leaf)" { & $lgpo /g $b }) { $State.GpoApplied += $b } }
    Invoke-Step 'gpupdate /force' { gpupdate /force }
    if ($DryRun) { return }
    # The STIG can change access to THIS box in two ways independent of any rule this script added: firewall rule
    # merging, and RDP NLA. Both are worth a loud warning right after the GPO that might have changed them applies.
    $mergeOff = foreach ($prof in 'DomainProfile', 'StandardProfile', 'PrivateProfile', 'PublicProfile') {
        $v = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$prof" -Name AllowLocalPolicyMerge -ErrorAction SilentlyContinue).AllowLocalPolicyMerge
        if ($null -ne $v -and $v -eq 0) { $prof }
    }
    if ($mergeOff) { Write-Log "WARNING: GPO sets AllowLocalPolicyMerge=0 for $($mergeOff -join ', ') - local HPCC4-Keep-*/Allow firewall rules are now IGNORED by policy. RDP/SSH may be unreachable even with the rule present. See gpo-verification-checklist.md." }
    if ((Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication -eq 1) {
        Write-Log 'WARNING: GPO enabled RDP Network Level Authentication - if you get disconnected now, reconnect with an NLA-capable RDP client.'
    }
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
    if (-not (Invoke-Step 'lock down ToolsDir' { Lock-AdminOnlyAcl $ToolsDir @('*S-1-5-32-545:(OI)(CI)RX') }) -and -not $DryRun) { return }
    if ($ToolsZip) { Expand-ToolsZip }
    # AV installer: no hash to pin (the vendor updates it), so it only gets opened later if it carries a valid digital
    # signature and, if $AvInstallerExpectedSigner is set, that signature matches the expected signer too.
    if ($AvInstallerUrl) {
        $av = Join-Path $ToolsDir (Split-Path $AvInstallerUrl -Leaf)
        if (Invoke-Step "download $(Split-Path $AvInstallerUrl -Leaf)" { Invoke-WebRequest $AvInstallerUrl -OutFile $av -UseBasicParsing }) {
            $sig = Get-AuthenticodeSignature $av
            if ($sig.Status -ne 'Valid') { Write-Log "WARNING: $av signature is $($sig.Status) - it will NOT be opened." }
            elseif ($AvInstallerExpectedSigner -and $sig.SignerCertificate.Subject -notmatch [regex]::Escape($AvInstallerExpectedSigner)) { Write-Log "WARNING: $av is validly signed but not by the expected signer ('$AvInstallerExpectedSigner') - it will NOT be opened. Actual signer: $($sig.SignerCertificate.Subject)" }
            else { $State.AvInstaller = $av; Write-Log "AV installer signed by: $($sig.SignerCertificate.Subject)" }
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
    Write-Log "Backup: $($State.BackupDir) | Uncovered ports: $($State.Uncovered.Count) | Old inbound rules removed: $($State.Purge) | Firewall on: $($State.FirewallOn)"
    Write-Log "Rules added: $($State.RulesAdded -join ', ') | Blocks refused: $($State.BlocksRefused -join ', ') | Accounts deleted: $($State.Deleted -join ', ') | Passwords changed: $($State.Changed -join ', ')"
    Write-Log "Extra services disabled: $($State.ServicesDisabled -join ', ')"
    Write-Log "Persistence entries: $($State.Persistence.Count) ($(@($State.Persistence | Where-Object { $_.Suspicious }).Count) suspicious) | DoD GPOs applied: $($State.GpoApplied.Count)"
    Write-Log "Tools installed: $($State.ToolsInstalled) | Hash check: $($State.HashChecked) | AV installer: $($State.AvInstaller) | Locked: $($State.Locked -join ', ') | Failures: $($State.Failures -join ', ')"
    if (-not $State.GpoApplied.Count) { Write-Log 'WARNING: no DoD STIG GPOs were applied this run - baseline hardening in gpo-verification-checklist.md (RDP NLA, WDigest, SMBv1, SMB signing, Guest account) was NOT applied by anything unless you did it by hand.' }
}
# Clears PS history and Windows Event Logs; directory self-deletion is refused pending safe exact-file cleanup.
function Invoke-Cleanup {
    if ($DryRun) { Write-Log 'WOULD: clear PS history, clear event logs; directory self-deletion is refused - delete the script by hand'; return }
    Invoke-Step 'clear PS history' { Remove-Item (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue }
    Invoke-Step 'clear event logs' {
        Get-WinEvent -ListLog * | ForEach-Object {
            try { [Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) } catch {}
        }
    }
    $scriptDir  = $PSScriptRoot
    # Never self-delete a folder that holds $OutDir/$ToolsDir - that would destroy the backups, ACL-restore files and
    # persistence report this very run just produced, with no way to get them back.
    try {
        $scriptDirFull = (Resolve-Path $scriptDir -ErrorAction Stop).Path
        if ($scriptDirFull -isnot [string] -or -not $scriptDirFull) { throw 'No resolved directory string' }
    } catch { Write-Log "WARNING: not self-deleting $scriptDir - unresolved script directory. Delete the script by hand once you've saved anything you need."; return }
    $unsafe = @()
    foreach ($candidate in @($OutDir, $ToolsDir)) {
        if (-not $candidate) { continue }
        # Keep the input separately: catch's $_ is an ErrorRecord, never a path.
        try {
            $full = (Resolve-Path $candidate -ErrorAction Stop).Path
            if ($full -isnot [string] -or -not $full) { throw 'No resolved candidate string' }
        } catch { Write-Log "WARNING: not self-deleting $scriptDir - unresolved path $candidate. Delete the script by hand once you've saved anything you need."; return }
        if ($full -ieq $scriptDirFull -or $full.StartsWith("$scriptDirFull\", [StringComparison]::OrdinalIgnoreCase)) { $unsafe += $candidate }
    }
    if ($unsafe.Count) { Write-Log "WARNING: not self-deleting $scriptDir - it contains $($unsafe -join ', '). Delete the script by hand once you've saved anything you need from there."; return }
    Write-Log "WARNING: not self-deleting $scriptDir - directory deletion is refused pending safe exact-file cleanup. Delete the script by hand once you've saved anything you need."
}
function Main {
    if (-not (Test-IsAdmin)) { Write-Log 'Must be run elevated (as Administrator). Exiting.'; exit 1 }
    $null = Initialize-Setup   # $null = hides Invoke-Step's True/False results from the console
    if ($Unlock) { $null = Unlock-Paths; return }
    $null = Backup-Targets
    # finally: the service ports reopen even if a step fails or you press Ctrl+C, so services never stay closed.
    try { $null = Set-FirewallLockdown; $null = Remove-UnauthorizedUsers; $null = Set-LocalPasswords; $null = Disable-ExtraServices; $null = Get-PersistenceReport; $null = Install-DodGpo; $null = Install-Tools; $null = Lock-Paths }
    finally { $null = Open-ServicePorts; Write-Summary }
    # Only after a normal finish, with services back up: open the AV installer for you to click through (it needs internet).
    if ($State.AvInstaller) { Write-Log "Opening the AV installer: $($State.AvInstaller)"; $null = Invoke-Step 'open AV installer' { Start-Process $State.AvInstaller } }
    if ($Cleanup) { $null = Invoke-Cleanup }
}
if ($MyInvocation.InvocationName -ne '.') { Main }
