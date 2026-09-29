# watch-hpcc4.ps1 - READ-ONLY live change monitor. Test/dev tool only; never run it against the actual scored box.
# It never changes anything: it polls system state on an interval and prints every change the moment it's detected,
# then prints a full BEFORE/AFTER table comparing the very first snapshot to the last one when you stop it.
#
# Usage: run this FIRST, in its own window, before running hpcc4-simple.ps1 or reset-hpcc4.ps1 elsewhere:
#   .\watch-hpcc4.ps1
#   .\watch-hpcc4.ps1 -IntervalSeconds 1 -MainScript C:\path\to\your-copy.ps1
#   .\watch-hpcc4.ps1 -DurationSeconds 300   # stop automatically after 5 minutes instead of Ctrl+C
#
# It reads the same tunables ($OutDir, $ToolsDir, $LockPaths) from hpcc4-simple.ps1, the same way reset-hpcc4.ps1
# does, and reuses its read-only helpers (Get-ListeningPorts, Test-EveryoneDeny) instead of reimplementing them.
#
# Poll-based, not event-based: a change made and then reverted within one interval can be missed by the live feed -
# it would only show in the BEFORE/AFTER table if the end state actually differs from the very first snapshot.
# Read-only, so it does not require elevation, but some registry/firewall reads return more complete results when
# run elevated - run it as Administrator if you can.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', 'Write-Log', Justification = 'Defined in hpcc4-simple.ps1')]
param([string]$MainScript = '', [int]$IntervalSeconds = 2, [int]$DurationSeconds = 0)
if (-not $MainScript) { $MainScript = Join-Path $PSScriptRoot 'hpcc4-simple.ps1' }
if (-not (Test-Path $MainScript)) { Write-Host "Can't find $MainScript. Put this file next to hpcc4-simple.ps1, or run: .\watch-hpcc4.ps1 -MainScript <path to it>." -ForegroundColor Red; exit 1 }
if (-not (Select-String -Path $MainScript -SimpleMatch '# HPCC4-SIMPLE-SCRIPT v1' -Quiet)) {
    Write-Host "$MainScript doesn't look like hpcc4-simple.ps1 (missing its identity marker). Nothing watched." -ForegroundColor Red; exit 1
}
. $MainScript   # loads tunables and read-only helpers only; the guard at its end stops it from running

function Write-Change { param([string]$Line) Write-Host "$(Get-Date -Format 'HH:mm:ss') $Line" -ForegroundColor Yellow }

# One point-in-time read of everything hpcc4-simple.ps1 / reset-hpcc4.ps1 can touch.
function Get-Snapshot {
    $s = [ordered]@{}
    $s.Users = @(Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name, @{n = 'SID'; e = { $_.SID.Value } }, Enabled, PasswordLastSet)
    $s.FirewallProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled, DefaultInboundAction)
    $s.FirewallRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Select-Object Name, Action, Enabled)
    $s.Services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object Name, State, StartMode)
    $s.Tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object @{n = 'Key'; e = { "$($_.TaskPath)$($_.TaskName)" } }, State)
    $s.Registry = [ordered]@{
        'RDP NLA (policy)'                = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
        'RDP NLA (control)'                = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
        'WDigest UseLogonCredential'       = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
        'SMB1 enabled'                     = $(try { (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $null })
        'SMB signing required'             = $(try { (Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature } catch { $null })
        'Guest (RID 501) enabled'          = (Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { ($_.SID.Value -split '-')[-1] -eq 501 } | Select-Object -ExpandProperty Enabled)
        'Administrator (RID 500) name'     = (Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { ($_.SID.Value -split '-')[-1] -eq 500 } | Select-Object -ExpandProperty Name)
        'Administrator (RID 500) enabled'  = (Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { ($_.SID.Value -split '-')[-1] -eq 500 } | Select-Object -ExpandProperty Enabled)
        'AllowLocalPolicyMerge (Domain)'   = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' -Name AllowLocalPolicyMerge -ErrorAction SilentlyContinue).AllowLocalPolicyMerge
        'AllowLocalPolicyMerge (Private)'  = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' -Name AllowLocalPolicyMerge -ErrorAction SilentlyContinue).AllowLocalPolicyMerge
        'AllowLocalPolicyMerge (Public)'   = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' -Name AllowLocalPolicyMerge -ErrorAction SilentlyContinue).AllowLocalPolicyMerge
        'Machine PATH'                     = (Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').GetValue('Path', '', 'DoNotExpandEnvironmentNames')
        'Sysinternals EULA accepted'       = (Get-ItemProperty 'HKCU:\Software\Sysinternals' -Name EulaAccepted -ErrorAction SilentlyContinue).EulaAccepted
    }
    $s.LockedPaths = [ordered]@{}
    foreach ($p in @($LockPaths)) { $s.LockedPaths[$p] = if (Test-Path $p -ErrorAction SilentlyContinue) { Test-EveryoneDeny $p } else { $null } }
    $s.ListeningPorts = @(Get-ListeningPorts | ForEach-Object { "$($_.Proto):$($_.Port)" })
    $s.OutDirFiles = if (Test-Path $OutDir) { @(Get-ChildItem $OutDir -Recurse -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName) } else { @() }
    $s.ToolsDirFiles = if (Test-Path $ToolsDir) { @(Get-ChildItem $ToolsDir -Recurse -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName) } else { @() }
    $s.Sysmon = [bool](Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue)
    $s
}

# Generic diffs, reused across every category above instead of one bespoke comparison per category.
function Compare-KeyedList {
    param([string]$Label, [array]$Before, [array]$After, [string]$KeyProp, [string[]]$WatchProps)
    $beforeMap = @{}; foreach ($i in $Before) { $beforeMap[$i.$KeyProp] = $i }
    $afterMap = @{}; foreach ($i in $After) { $afterMap[$i.$KeyProp] = $i }
    foreach ($k in $afterMap.Keys) {
        if (-not $beforeMap.ContainsKey($k)) { Write-Change "$Label ADDED: $k"; continue }
        foreach ($p in $WatchProps) {
            $b = $beforeMap[$k].$p; $a = $afterMap[$k].$p
            if ("$b" -ne "$a") { Write-Change "$Label CHANGED: $k -> $p ($b -> $a)" }
        }
    }
    foreach ($k in $beforeMap.Keys) { if (-not $afterMap.ContainsKey($k)) { Write-Change "$Label REMOVED: $k" } }
}
function Compare-Set {
    param([string]$Label, [string[]]$Before, [string[]]$After)
    @($After | Where-Object { $Before -notcontains $_ }) | ForEach-Object { Write-Change "$Label ADDED: $_" }
    @($Before | Where-Object { $After -notcontains $_ }) | ForEach-Object { Write-Change "$Label REMOVED: $_" }
}
function Compare-Scalars {
    param([string]$Label, [System.Collections.IDictionary]$Before, [System.Collections.IDictionary]$After)
    foreach ($k in $After.Keys) { $b = $Before[$k]; $a = $After[$k]; if ("$b" -ne "$a") { Write-Change "$Label`: $k ($b -> $a)" } }
}
function Compare-Snapshots {
    param($Before, $After)
    Compare-KeyedList 'USER' $Before.Users $After.Users 'Name' @('Enabled', 'PasswordLastSet')
    Compare-KeyedList 'FIREWALL PROFILE' $Before.FirewallProfiles $After.FirewallProfiles 'Name' @('Enabled', 'DefaultInboundAction')
    Compare-KeyedList 'FIREWALL RULE' $Before.FirewallRules $After.FirewallRules 'Name' @('Action', 'Enabled')
    Compare-KeyedList 'SERVICE' $Before.Services $After.Services 'Name' @('State', 'StartMode')
    Compare-KeyedList 'SCHEDULED TASK' $Before.Tasks $After.Tasks 'Key' @('State')
    Compare-Scalars 'REGISTRY' $Before.Registry $After.Registry
    Compare-Scalars 'ACL LOCK' $Before.LockedPaths $After.LockedPaths
    Compare-Set 'LISTENING PORT' $Before.ListeningPorts $After.ListeningPorts
    Compare-Set 'OUTDIR FILE' $Before.OutDirFiles $After.OutDirFiles
    Compare-Set 'TOOLSDIR FILE' $Before.ToolsDirFiles $After.ToolsDirFiles
    if ($Before.Sysmon -ne $After.Sysmon) { Write-Change "SYSMON installed: $($Before.Sysmon) -> $($After.Sysmon)" }
}

Write-Log "watch-hpcc4: watching against $MainScript's tunables (OutDir=$OutDir, ToolsDir=$ToolsDir, LockPaths=$($LockPaths -join ', ')). Polling every ${IntervalSeconds}s. Ctrl+C to stop and print the BEFORE/AFTER summary."
$first = Get-Snapshot
$prev = $first
$startedAt = Get-Date
try {
    while ($true) {
        if ($DurationSeconds -gt 0 -and ((Get-Date) - $startedAt).TotalSeconds -ge $DurationSeconds) { break }
        Start-Sleep -Seconds $IntervalSeconds
        $cur = Get-Snapshot
        Compare-Snapshots $prev $cur
        $prev = $cur
    }
} finally {
    Write-Log '--- BEFORE / AFTER SUMMARY (first snapshot vs. right now) ---'
    Compare-Snapshots $first $prev
    Write-Log '--- end summary (nothing printed above means nothing changed since watch-hpcc4.ps1 started) ---'
}
