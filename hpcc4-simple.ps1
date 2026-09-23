# HPCC4 defensive helper: backup, firewall, local passwords, tools, ACL lock.
# Every change runs through Invoke-Step so one failure never stops the rest. PS 4.0-5.1, Server 2012 R2-2025.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', 'Write-Log', Justification = 'Defined in this script')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', 'Get-LocalUser', Justification = 'Guarded by Get-Command; ADSI fallback')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', 'Set-LocalUser', Justification = 'Guarded by Get-Command; ADSI fallback')]
param([switch]$DryRun, [switch]$Unlock)
# ---- Tunables (nothing else in this script is hardcoded) ----
$KeepOpenTcp    = @(22)        # open for the WHOLE run, along with the live RDP port (22 = SSH, just in case)
$AllowTcp       = @(3389)      # scored-service TCP ports; opened at the END of the run
$AllowUdp       = @()          # scored-service UDP ports, e.g. 53 for DNS; opened at the END of the run
$BlockTcp       = @()          # inbound TCP to block, e.g. 21, 23
$BlockUdp       = @()          # inbound UDP to block
$ExcludeUsers   = @()          # never change these passwords
$ToolsDir       = 'C:\Tools'
$ToolsZip       = ''           # local path OR https URL to your tools zip
$ToolsZipSha256 = ''           # if set, reject a zip whose SHA256 doesn't match
$InstallSysmon  = $false       # true = install/update Sysmon if files are in $ToolsDir
$BackupPaths    = @('C:\Windows\System32\drivers\etc\hosts')
$LockPaths      = @('C:\Windows\System32\drivers\etc\hosts')
$OutDir         = 'C:\HPCC4'
$State = @{ IsDC = $false; RdpPort = 3389; BackupDir = ''; Uncovered = @(); Purge = $false; Enable = $true; FirewallOn = $false; RulesAdded = @(); BlocksRefused = @(); Changed = @(); ToolsInstalled = $false; HashChecked = 'no'; Locked = @(); Failures = @() }
function Write-Log { param([string]$Message); $line = "$(Get-Date -Format 'HH:mm:ss') $Message"; Write-Host $line; if (Test-Path $OutDir) { Add-Content -Path (Join-Path $OutDir 'log.txt') -Value $line } }
# Runs $Action; -DryRun runs nothing. Checks $LASTEXITCODE for native commands (0-7 ok for robocopy -RobocopyCodes, else only 0 ok). Never throws.
function Invoke-Step {
    param([Parameter(Position = 0)][string]$Name, [Parameter(Position = 1)][scriptblock]$Action, [switch]$RobocopyCodes)
    if ($DryRun) { Write-Log "WOULD: $Name"; return $false }
    $global:LASTEXITCODE = 0
    try {
        $out = & $Action 2>&1
        # Non-terminating cmdlet errors (e.g. Set-LocalUser rejecting a password) count as failures; native stderr lines don't.
        $errs = @($out | Where-Object { $_ -is [Management.Automation.ErrorRecord] -and $_.FullyQualifiedErrorId -notlike 'NativeCommandError*' })
        $failed = if ($RobocopyCodes) { $LASTEXITCODE -ge 8 } else { $LASTEXITCODE -ne 0 }
        if (-not $failed -and $errs.Count -eq 0) { return $true }
        Write-Log "FAILED: ${Name}: exit $LASTEXITCODE $(if ($errs.Count) { $errs[0] } else { ($out | Select-Object -Last 1) -join ' ' })"
    } catch { Write-Log "FAILED: ${Name}: $($_.Exception.Message)" }
    $State.Failures += $Name; return $false
}
function Test-IsAdmin { $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
function Get-NormalizedName { param([string]$Name); if ([string]::IsNullOrEmpty($Name)) { return '' }; $i = $Name.LastIndexOf('\'); if ($i -ge 0) { $Name = $Name.Substring($i + 1) }; return $Name.ToLowerInvariant() }
function Get-ServiceAccounts { Get-CimInstance -ClassName Win32_Service | ForEach-Object { $_.StartName } }
function Get-AppPoolAccounts { $appcmd = Join-Path $env:windir 'system32\inetsrv\appcmd.exe'; if (-not (Test-Path $appcmd)) { return @() }; return @(& $appcmd list apppool /text:processModel.userName) }
function Get-TaskAccounts { if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) { return Get-ScheduledTask | ForEach-Object { $_.Principal.UserId } }; return (schtasks /query /v /fo csv | ConvertFrom-Csv) | ForEach-Object { $_.'Run As User' } }
function Get-LocalEnabledUsers {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) { return Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object { $_.Name } }
    return ([ADSI]"WinNT://$env:COMPUTERNAME").Children | Where-Object { $_.SchemaClassName -eq 'user' -and -not ($_.UserFlags.Value -band 2) } | ForEach-Object { $_.Name.ToString() }
}
function Get-PasswordTargets {
    $raw = @($ExcludeUsers) + @(Get-ServiceAccounts) + @(Get-AppPoolAccounts) + @(Get-TaskAccounts)
    $excluded = @($raw | ForEach-Object { Get-NormalizedName $_ } | Where-Object { $_ })
    return @(Get-LocalEnabledUsers) | Where-Object { $excluded -notcontains (Get-NormalizedName $_) }
}
function Get-ListeningPorts {
    $ports = @()
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        foreach ($c in Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue) { $ports += [pscustomobject]@{ Proto = 'TCP'; Port = [int]$c.LocalPort; Process = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).Name } }
        foreach ($c in Get-NetUDPEndpoint -ErrorAction SilentlyContinue) { $ports += [pscustomobject]@{ Proto = 'UDP'; Port = [int]$c.LocalPort; Process = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).Name } }
    } else {
        # netstat -ano fallback: port is after the last ':' of the local address column.
        foreach ($line in (netstat -ano)) {
            if ($line -notmatch '^\s*(TCP|UDP)\s+\S+:(\d+)\s+\S+\s+(?:(\S+)\s+)?(\d+)\s*$') { continue }; if ($Matches[1] -eq 'TCP' -and $Matches[3] -ne 'LISTENING') { continue }
            $ports += [pscustomobject]@{ Proto = $Matches[1]; Port = [int]$Matches[2]; Process = (Get-Process -Id $Matches[4] -ErrorAction SilentlyContinue).Name }
        }
    }
    $seen = @{}; $result = @()
    foreach ($p in $ports) { $key = "$($p.Proto):$($p.Port)"; if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $result += $p } }
    return $result
}
function Get-InboundAllowPorts {
    $result = @()
    if (-not (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)) { return $result }
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and $_.Enabled -eq $true }
    foreach ($r in $rules) {
        foreach ($f in ($r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
            $proto = $f.Protocol.ToUpper()
            foreach ($lp in @($f.LocalPort)) {
                if ($lp -match '^\d+$') { $result += '{0}:{1}' -f $proto, $lp }
                elseif ($lp -match '^(\d+)-(\d+)$') { for ($i = [int]$Matches[1]; $i -le [int]$Matches[2]; $i++) { $result += '{0}:{1}' -f $proto, $i } }
            }
        }
    }
    return $result
}
function Get-AclSaveFile {
    param([string]$Path); $sha = [Security.Cryptography.SHA256]::Create()
    $hash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Path.ToLowerInvariant()))) -replace '-', '').Substring(0, 8).ToLowerInvariant()
    $safe = $Path; foreach ($ch in @(':', '\', '/')) { $safe = $safe.Replace($ch, '_') }
    return Join-Path $OutDir "acl-$safe-$hash.txt"
}
function Test-EveryoneDeny {
    param([string]$Path); $acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue; if (-not $acl) { return $false }
    foreach ($ace in $acl.Access) { if ($ace.AccessControlType -ne 'Deny') { continue }; try { if ($ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0') { return $true } } catch { } }
    return $false
}
function Add-Hpcc4Rule {
    param([string]$Proto, [int]$Port, [string]$RuleAction, [bool]$HasCmdlets, [string]$Label = $RuleAction)
    $n = "HPCC4-$Label-$Proto-$Port"
    if ($HasCmdlets) { $ok = Invoke-Step $n { New-NetFirewallRule -Name $n -DisplayName $n -Direction Inbound -Protocol $Proto -LocalPort $Port -Action $RuleAction } }
    else { $act = $RuleAction.ToLower(); $ok = Invoke-Step $n { netsh advfirewall firewall add rule name=$n dir=in action=$act protocol=$Proto localport=$Port } }
    if ($ok) { $State.RulesAdded += $n }
}
# Ports that stay open for the whole run: the live RDP port plus $KeepOpenTcp. Their rules are named HPCC4-Keep-TCP-<port>.
function Get-KeepPorts { return @(@($State.RdpPort) + @($KeepOpenTcp) | ForEach-Object { [int]$_ } | Select-Object -Unique) }
function Test-Hpcc4Rule {
    param([string]$Name, [bool]$HasCmdlets)
    if ($HasCmdlets) { return [bool](Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue) }
    netsh advfirewall firewall show rule name=$Name | Out-Null; return ($LASTEXITCODE -eq 0)
}
# Removes local inbound rules. -All: every rule except the built-in DHCP ones; otherwise only old HPCC4-* rules. Keep rules are never removed.
function Remove-InboundRules {
    param([bool]$All, [bool]$HasCmdlets)
    $keep = @(Get-KeepPorts | ForEach-Object { "HPCC4-Keep-TCP-$_" })
    if ($HasCmdlets) { $names = @(Get-NetFirewallRule -Direction Inbound -PolicyStore PersistentStore -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) }
    else { $names = @(netsh advfirewall firewall show rule name=all dir=in | ForEach-Object { if ($_ -match '^Rule Name:\s+(.+?)\s*$') { $Matches[1] } }) }
    $dhcp = @('CoreNet-DHCP*', 'Core Networking - Dynamic Host Configuration Protocol*')   # built-in DHCP rules (by name, and by display name for netsh)
    $names = @($names | Select-Object -Unique | Where-Object { $n = $_; $keep -notcontains $n -and -not ($dhcp | Where-Object { $n -like $_ }) -and ($All -or $n -like 'HPCC4-*') })
    if ($names.Count -eq 0) { return }
    if ($HasCmdlets) { Invoke-Step "remove $($names.Count) inbound firewall rules" { Remove-NetFirewallRule -Name $names } }
    else { Invoke-Step "remove $($names.Count) inbound firewall rules" { $rc = 0; foreach ($n in $names) { netsh advfirewall firewall delete rule "name=$n" dir=in | Out-Null; if ($LASTEXITCODE) { $rc = $LASTEXITCODE } }; $global:LASTEXITCODE = $rc } }
}
function Enable-Firewall {
    param([bool]$BlockInbound, [bool]$HasCmdlets)
    if ($HasCmdlets -and $BlockInbound) { return Invoke-Step 'firewall on, block inbound by default' { Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block } }
    if ($HasCmdlets) { return Invoke-Step 'firewall on' { Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True } }
    if ($BlockInbound) { return Invoke-Step 'firewall on, block inbound by default' { netsh advfirewall set allprofiles state on; if ($LASTEXITCODE -eq 0) { netsh advfirewall set allprofiles firewallpolicy 'blockinbound,allowoutbound' } } }
    return Invoke-Step 'firewall on' { netsh advfirewall set allprofiles state on }
}
function ConvertFrom-SecureText {
    param([Security.SecureString]$Secure); $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
function Get-FileHashHex {
    param([string]$Path); if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) { return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
    $stream = [IO.File]::OpenRead($Path)
    try { return ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($stream)) -replace '-', '').ToLowerInvariant() } finally { $stream.Close() }
}
function Add-ToolsDirToPath {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $old = (Get-Item $key).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    if (@($old -split ';') | Where-Object { $_.TrimEnd('\') -ieq $ToolsDir.TrimEnd('\') }) { return }
    New-ItemProperty -Path $key -Name 'Path' -Value "$old;$ToolsDir" -PropertyType ExpandString -Force | Out-Null
}
function Initialize-Setup {
    $reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction SilentlyContinue
    $State.RdpPort = if ($reg -and $reg.PortNumber) { $reg.PortNumber } else { 3389 }
    $State.IsDC = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -in 4, 5
    Invoke-Step 'create OutDir' { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }; Invoke-Step 'lock down OutDir' { icacls $OutDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' }
}
function Backup-Targets {
    $dest = Join-Path $OutDir "backup\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $State.BackupDir = $dest
    foreach ($path in $BackupPaths) {
        if (-not (Test-Path $path)) { Write-Log "backup skip (missing): $path"; continue }
        $item = Get-Item $path
        if ($item.PSIsContainer) { $target = Join-Path $dest $path.Remove(1, 1); Invoke-Step "backup $path" { robocopy $path $target /E /R:1 /W:1 } -RobocopyCodes }
        else { $target = Join-Path $dest $item.DirectoryName.Remove(1, 1); Invoke-Step "backup $path" { robocopy $item.DirectoryName $target $item.Name /R:1 /W:1 } -RobocopyCodes }
    }
    Invoke-Step 'export firewall' { $wfw = Join-Path $OutDir 'firewall-before.wfw'; if (Test-Path $wfw) { Write-Log 'firewall-before.wfw exists, skipping export'; return }; netsh advfirewall export $wfw }
}
# Start of run: close every inbound port except RDP, $KeepOpenTcp and DHCP. Service ports reopen in Open-ServicePorts at the end.
function Set-FirewallLockdown {
    $hasCmdlets = [bool](Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)
    $keep = Get-KeepPorts
    $State.Enable = $true; $State.Purge = $true
    if ($State.IsDC) { $State.Purge = $false; Write-Log 'WARNING: domain controller - NOT removing existing firewall rules (AD needs dynamic RPC ports).' }
    elseif (-not $DryRun -and -not (Test-Path (Join-Path $OutDir 'firewall-before.wfw'))) { $State.Purge = $false; Write-Log 'WARNING: no firewall backup (firewall-before.wfw) - NOT removing existing firewall rules.' }
    $covered = @(@($AllowTcp) + $keep | ForEach-Object { "TCP:$_" }) + @(@($AllowUdp) | ForEach-Object { "UDP:$_" })
    if (-not $State.Purge) { $covered += @(Get-InboundAllowPorts) }   # without a purge, existing rules keep covering their ports
    $State.Uncovered = @()
    foreach ($l in @(Get-ListeningPorts)) {
        if ($covered -contains "$($l.Proto):$($l.Port)") { continue }
        $State.Uncovered += $l; Write-Log "WARNING: $($l.Proto) $($l.Port) ($($l.Process)) is listening but not covered - this service will be blocked once the firewall is on."
    }
    if ($State.Uncovered.Count -gt 0 -and -not $DryRun -and (Read-Host 'Uncovered ports found. Lock down the firewall anyway? y/N') -ne 'y') {
        $State.Enable = $false; $State.Purge = $false; Write-Log 'Firewall left as it is; HPCC4 rules will still be added at the end.'
    }
    # Add the keep rules BEFORE removing anything, so RDP never has a gap. Keep rules that already exist are left alone.
    foreach ($p in $keep) { if (-not (Test-Hpcc4Rule "HPCC4-Keep-TCP-$p" $hasCmdlets)) { Add-Hpcc4Rule -Proto 'TCP' -Port $p -RuleAction 'Allow' -Label 'Keep' -HasCmdlets $hasCmdlets } }
    if (-not $State.Purge) { return }
    Remove-InboundRules -All $true -HasCmdlets $hasCmdlets
    $State.FirewallOn = Enable-Firewall -BlockInbound $true -HasCmdlets $hasCmdlets
}
# End of run (always runs, even after a failure or Ctrl+C): open the scored-service ports from the tunables.
function Open-ServicePorts {
    $hasCmdlets = [bool](Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)
    $keep = Get-KeepPorts
    if (-not $State.Purge) { Remove-InboundRules -All $false -HasCmdlets $hasCmdlets }   # the purge already removed old HPCC4 rules
    $allowTcp = @($AllowTcp) | Select-Object -Unique; $allowUdp = @($AllowUdp) | Select-Object -Unique
    foreach ($p in @($allowTcp | Where-Object { $keep -notcontains $_ })) { Add-Hpcc4Rule -Proto 'TCP' -Port $p -RuleAction 'Allow' -HasCmdlets $hasCmdlets }
    foreach ($p in @($allowUdp)) { Add-Hpcc4Rule -Proto 'UDP' -Port $p -RuleAction 'Allow' -HasCmdlets $hasCmdlets }
    foreach ($p in @($BlockTcp)) { if ($allowTcp -contains $p -or $keep -contains $p) { Write-Log "REFUSED block TCP $p - also allowed / RDP / keep-open port"; $State.BlocksRefused += "TCP:$p"; continue }; Add-Hpcc4Rule -Proto 'TCP' -Port $p -RuleAction 'Block' -HasCmdlets $hasCmdlets }
    foreach ($p in @($BlockUdp)) { if ($allowUdp -contains $p) { Write-Log "REFUSED block UDP $p - also allowed"; $State.BlocksRefused += "UDP:$p"; continue }; Add-Hpcc4Rule -Proto 'UDP' -Port $p -RuleAction 'Block' -HasCmdlets $hasCmdlets }
    if ($State.Enable -and -not $State.FirewallOn) { $State.FirewallOn = Enable-Firewall -BlockInbound $false -HasCmdlets $hasCmdlets }
}
function Set-LocalPasswords {
    if ($State.IsDC) { Write-Log 'Skipping password changes: this is a domain controller.'; return }
    $targets = @(Get-PasswordTargets)
    Write-Log "Password targets: $($targets -join ', ')"
    if ($DryRun) { Write-Log 'WOULD: change passwords for targets above'; return }
    if ((Read-Host 'Change these passwords? y/N') -ne 'y') { return }
    $secure = $null
    for ($i = 0; $i -lt 3; $i++) {
        $p1 = Read-Host -Prompt 'New password (blank to skip)' -AsSecureString; if ($p1.Length -eq 0) { return }
        $p2 = Read-Host -Prompt 'Confirm password' -AsSecureString
        $t1 = ConvertFrom-SecureText $p1; $t2 = ConvertFrom-SecureText $p2
        $match = ($t1 -ceq $t2); $t1 = $null; $t2 = $null; if ($match) { $secure = $p1; break }
        Write-Log 'Passwords did not match, try again.'
    }
    if (-not $secure) { Write-Log 'Password entry failed after 3 tries.'; return }
    $hasCmdlet = [bool](Get-Command Set-LocalUser -ErrorAction SilentlyContinue)
    foreach ($u in $targets) {
        $ok = Invoke-Step "password $u" {
            if ($hasCmdlet) { Set-LocalUser -Name $u -Password $secure }
            else {
                $plain = ConvertFrom-SecureText $secure
                try { $obj = [ADSI]"WinNT://$env:COMPUTERNAME/$u,user"; $obj.SetPassword($plain); $obj.SetInfo() } finally { $plain = $null }
            }
        }
        if ($ok) { $State.Changed += $u }
    }
    $secure = $null
    Write-Log "Changed accounts: $($State.Changed -join ', ')"
    Write-Log 'SUBMIT PASSWORD CHANGES TO THE SCOREBOARD.'
}
function Install-Tools {
    $zipPath = $null
    if ($ToolsZip -match '^https?://') {
        $ok = Invoke-Step 'download tools zip' {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $ToolsZip -OutFile (Join-Path $OutDir 'tools.zip') -UseBasicParsing
        }
        if ($ok) { $zipPath = Join-Path $OutDir 'tools.zip' }   # never fall back to a stale zip from an earlier run
    } elseif ($ToolsZip -and (Test-Path $ToolsZip)) { $zipPath = $ToolsZip }
    if (-not $zipPath) { Write-Log 'No tools zip available; skipping tools install.'; return }
    if ($ToolsZipSha256) { if ((Get-FileHashHex $zipPath) -ne $ToolsZipSha256.ToLowerInvariant()) { Write-Log 'Tools zip hash MISMATCH - rejected.'; $State.HashChecked = 'MISMATCH - rejected'; return }; $State.HashChecked = 'ok' } else { $State.HashChecked = 'not set' }
    $extractDir = Join-Path $OutDir "tools-extract-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    if (-not (Invoke-Step 'extract tools zip' { Add-Type -AssemblyName System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractDir) })) { return }
    Invoke-Step 'create ToolsDir' { New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null }
    # Never copy tools into, or put on PATH, a folder that non-admins might be able to write to.
    if (-not (Invoke-Step 'lock down ToolsDir' { icacls $ToolsDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' })) { return }
    if (Invoke-Step 'copy tools into ToolsDir' { Copy-Item -Path (Join-Path $extractDir '*') -Destination $ToolsDir -Recurse -Force }) { $State.ToolsInstalled = $true }
    Invoke-Step 'add ToolsDir to PATH' { Add-ToolsDirToPath }
    Invoke-Step 'set Sysinternals EULA' { if (-not (Test-Path 'HKCU:\Software\Sysinternals')) { New-Item -Path 'HKCU:\Software' -Name 'Sysinternals' | Out-Null }; New-ItemProperty -Path 'HKCU:\Software\Sysinternals' -Name 'EulaAccepted' -Value 1 -PropertyType DWord -Force | Out-Null }
    if ($InstallSysmon) {
        $exe = Join-Path $ToolsDir 'Sysmon64.exe'; $cfg = Join-Path $ToolsDir 'sysmonconfig.xml'
        if ((Test-Path $exe) -and (Test-Path $cfg)) { $svc = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue; Invoke-Step 'install/update Sysmon' { if ($svc) { & $exe -c $cfg } else { & $exe -accepteula -i $cfg } } }
    }
}
function Lock-Paths {
    foreach ($path in $LockPaths) {
        if (-not (Test-Path $path)) { Write-Log "lock skip (missing): $path"; continue }
        $isDir = (Get-Item $path).PSIsContainer
        $save = Get-AclSaveFile $path
        # No saved ACL means -Unlock couldn't undo it, so never lock a path whose save failed.
        if (-not (Test-Path $save)) { if (-not (Invoke-Step "save ACL $path" { if ($isDir) { icacls $path /save $save /T } else { icacls $path /save $save }; Set-Content -Path ([IO.Path]::ChangeExtension($save, '.path')) -Value $path }) -and -not $DryRun) { continue } }
        Invoke-Step "attrib +R $path" { attrib +R $path }
        if (Test-EveryoneDeny $path) { $State.Locked += $path; continue }
        $deny = if ($isDir) { '*S-1-1-0:(OI)(CI)(W,D,DC)' } else { '*S-1-1-0:(W,D,DC)' }
        if (Invoke-Step "deny Everyone $path" { icacls $path /deny $deny }) { $State.Locked += $path }
    }
}
function Unlock-Paths {
    foreach ($save in @(Get-ChildItem -Path $OutDir -Filter 'acl-*.txt' -ErrorAction SilentlyContinue)) {
        $pathFile = [IO.Path]::ChangeExtension($save.FullName, '.path')
        if (-not (Test-Path $pathFile)) { continue }
        $target = (Get-Content -Path $pathFile -Raw).Trim()
        $parent = Split-Path $target -Parent
        if (-not (Invoke-Step "restore ACL $target" { icacls $parent /restore $save.FullName })) { continue }
        Invoke-Step "unlock attrib $target" { attrib -R $target }
        Invoke-Step "rename save files $target" { Rename-Item -Path $save.FullName -NewName "$($save.Name).restored"; Rename-Item -Path $pathFile -NewName "$(Split-Path $pathFile -Leaf).restored" }
    }
}
function Write-Summary {
    Write-Log "Backup folder: $($State.BackupDir) | Uncovered ports: $($State.Uncovered.Count) | Firewall on: $($State.FirewallOn) | Old inbound rules removed: $($State.Purge)"
    Write-Log "Rules added: $($State.RulesAdded -join ', ') | Blocks refused: $($State.BlocksRefused -join ', ')"
    Write-Log "Accounts changed: $($State.Changed -join ', ') | Tools installed: $($State.ToolsInstalled) | Hash check: $($State.HashChecked)"
    Write-Log "Locked paths: $($State.Locked -join ', ') | Failures: $($State.Failures -join ', ')"
}
function Main {
    if (-not (Test-IsAdmin)) { Write-Log 'Must be run elevated (as Administrator). Exiting.'; exit 1 }
    Initialize-Setup
    if ($Unlock) { Unlock-Paths; return }
    Backup-Targets
    # finally: the service ports reopen even if a step fails or you press Ctrl+C mid-run, so services never stay closed.
    try { Set-FirewallLockdown; Set-LocalPasswords; Install-Tools; Lock-Paths }
    finally { Open-ServicePorts; Write-Summary }
}
if ($MyInvocation.InvocationName -ne '.') { Main }
