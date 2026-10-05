# PreToolUse hook: flag edits to hpcc4-simple.ps1's tunables block ($KeepOpenTcp .. $DisableServices,
# roughly lines 5-26) for extra review, since a bad tunable can delete the wrong accounts, reset the
# wrong passwords, or lock the operator out. Does not block - asks for confirmation instead.
$ErrorActionPreference = 'Stop'
$input_ = [Console]::In.ReadToEnd() | ConvertFrom-Json
$toolName = $input_.tool_name
$filePath = $input_.tool_input.file_path

if ($toolName -notin @('Edit', 'MultiEdit', 'Write')) { exit 0 }
if (-not $filePath -or $filePath -notlike '*.ps1') { exit 0 }

# Identify the main script by content, not filename: reset-hpcc4.ps1's own -MainScript workflow means an operator may
# keep renamed per-competition copies (e.g. hpcc4-comp3.ps1), which a filename check would silently miss.
$marker = '# HPCC4-SIMPLE-SCRIPT v1'
$isMainScript = if ($toolName -eq 'Write') { "$($input_.tool_input.content)" -match [regex]::Escape($marker) } else { (Test-Path $filePath) -and (Select-String -Path $filePath -SimpleMatch $marker -Quiet) }
if (-not $isMainScript) { exit 0 }

$tunableNames = @(
    'KeepOpenTcp', 'AllowTcp', 'AllowUdp', 'BlockTcp', 'BlockUdp',
    'ExcludeUsers', 'AuthorizedUsers', 'ToolsDir', 'ToolsZip', 'ToolsZipSha256',
    'AvInstallerUrl', 'AvInstallerExpectedSigner', 'InstallSysmon', 'BackupPaths', 'LockPaths', 'OutDir',
    'DisableServices', 'DodGpoDir', 'LgpoExe'
)

$touchesTunable = $false
if ($toolName -eq 'Write') {
    $touchesTunable = $true   # full-file rewrite: can't tell what changed, always flag
} elseif ($toolName -eq 'Edit') {
    $text = "$($input_.tool_input.old_string)`n$($input_.tool_input.new_string)"
    $touchesTunable = $tunableNames | Where-Object { $text -match "\`$$_\b" } | Select-Object -First 1
} elseif ($toolName -eq 'MultiEdit') {
    $text = ($input_.tool_input.edits | ForEach-Object { "$($_.old_string)`n$($_.new_string)" }) -join "`n"
    $touchesTunable = $tunableNames | Where-Object { $text -match "\`$$_\b" } | Select-Object -First 1
}

if (-not $touchesTunable) { exit 0 }

$output = @{
    hookSpecificOutput = @{
        hookEventName            = 'PreToolUse'
        permissionDecision       = 'ask'
        permissionDecisionReason = "This edits hpcc4-simple.ps1's tunables block. These drive irreversible actions (account deletion, password resets, firewall changes) on whatever machine the script is next run against - confirm this is the right competition/target before proceeding."
    }
} | ConvertTo-Json -Depth 5 -Compress
Write-Output $output
exit 0
