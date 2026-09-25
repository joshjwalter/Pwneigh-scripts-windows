# reset-hpcc4.ps1 - FOR TEST VMs ONLY. Undoes what hpcc4-simple.ps1 changed, so you can run it again from a clean state.
# It reads the same tunables ($OutDir, $ToolsDir) from hpcc4-simple.ps1. By default that file must be in the same folder;
# if you renamed it or moved it, pass its path:  .\reset-hpcc4.ps1 -MainScript C:\path\to\your-copy.ps1
# It can't undo password changes: the old passwords were never stored.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', 'Write-Log', Justification = 'Defined in hpcc4-simple.ps1')]
param([string]$MainScript = '')
if (-not $MainScript) { $MainScript = Join-Path $PSScriptRoot 'hpcc4-simple.ps1' }
# Stop before doing anything if the main script is missing, or isn't the HPCC4 script: everything below needs its settings
# and helpers, and loading a different script (one without the dot-source guard) would RUN it.
if (-not (Test-Path $MainScript)) { Write-Host "Can't find $MainScript. Put this file next to hpcc4-simple.ps1, or run: .\reset-hpcc4.ps1 -MainScript <path to it>. Nothing changed." -ForegroundColor Red; exit 1 }
if (-not (Select-String -Path $MainScript -SimpleMatch "if (`$MyInvocation.InvocationName -ne '.') { Main }" -Quiet) -or -not (Select-String -Path $MainScript -SimpleMatch 'function Unlock-Paths' -Quiet)) {
    Write-Host "$MainScript doesn't look like hpcc4-simple.ps1, so it won't be loaded. Nothing changed." -ForegroundColor Red; exit 1
}
. $MainScript   # loads tunables and helpers only; the guard at its end stops it from running
if (-not $OutDir -or -not $ToolsDir) { Write-Host "$MainScript has an empty `$OutDir or `$ToolsDir. Nothing changed." -ForegroundColor Red; exit 1 }

if (-not (Test-IsAdmin)) { Write-Host 'Must be run elevated (as Administrator). Exiting.'; exit 1 }
Write-Host "This undoes hpcc4-simple.ps1 on THIS machine: firewall, file locks, machine PATH, Sysinternals EULA flag, Sysmon, and it DELETES $ToolsDir." -ForegroundColor Yellow
if ((Read-Host 'Type RESET to continue') -cne 'RESET') { Write-Host 'Nothing changed.'; exit 0 }

# 1. Firewall: put back the exact policy saved before the first run (rules, on/off state, default actions).
$wfw = Join-Path $OutDir 'firewall-before.wfw'
if (Test-Path $wfw) { Invoke-Step 'restore firewall from firewall-before.wfw' { netsh advfirewall import $wfw } }
else { Write-Log "WARNING: $wfw not found - firewall NOT restored." }

# 2. File locks: the same thing as hpcc4-simple.ps1 -Unlock.
Unlock-Paths

# 3. Sysmon: uninstall it if its service exists. (When installed, Sysmon copies itself into the Windows folder.)
if (Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue) {
    $exe = @((Join-Path $env:windir 'Sysmon64.exe'), (Join-Path $ToolsDir 'Sysmon64.exe')) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($exe) { Invoke-Step 'uninstall Sysmon' { & $exe -u force } }
    else { Write-Log 'WARNING: Sysmon service found but Sysmon64.exe not found - uninstall it by hand.' }
}

# 4. Machine PATH: remove the $ToolsDir entry, keeping %vars% in the other entries unexpanded.
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$old = (Get-Item $key).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
if (@($old -split ';') | Where-Object { $_.TrimEnd('\') -ieq $ToolsDir.TrimEnd('\') }) {
    $new = (@($old -split ';') | Where-Object { $_.TrimEnd('\') -ine $ToolsDir.TrimEnd('\') }) -join ';'
    Invoke-Step 'remove ToolsDir from machine PATH' { New-ItemProperty -Path $key -Name 'Path' -Value $new -PropertyType ExpandString -Force | Out-Null }
}

# 5. Sysinternals EULA flag (current user only, same as the main script sets it).
if (Get-ItemProperty -Path 'HKCU:\Software\Sysinternals' -Name 'EulaAccepted' -ErrorAction SilentlyContinue) {
    Invoke-Step 'remove Sysinternals EULA flag' { Remove-ItemProperty -Path 'HKCU:\Software\Sysinternals' -Name 'EulaAccepted' }
}

# 6. Tools folder.
if (Test-Path $ToolsDir) { Invoke-Step "delete $ToolsDir" { Remove-Item -Path $ToolsDir -Recurse -Force } }

Write-Log "Reset done. NOT undone: password changes and deleted accounts - fix those by hand. Backups are still in $OutDir."
if ($State.Failures.Count) { Write-Log "Failures: $($State.Failures -join ', ')" }
