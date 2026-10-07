# PreToolUse hook: flag edits to hpcc4-simple.ps1's tunables (the settings block at the top) for extra review, since a bad tunable can delete the wrong accounts, reset the
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

# A full-file Write can't be diffed, so it always counts. An edit counts if it mentions a tunable. The tunable names are read
# from the script itself (every top-level `$Name =` line above `$State =`), so this list can never go stale.
$touchesTunable = $toolName -eq 'Write'
if (-not $touchesTunable) {
    $top = ((Get-Content $filePath -Raw) -split '(?m)^\$State\s*=')[0]
    $tunableNames = [regex]::Matches($top, '(?m)^\$(\w+)\s*=') | ForEach-Object { $_.Groups[1].Value }
    $edits = if ($toolName -eq 'MultiEdit') { $input_.tool_input.edits } else { @($input_.tool_input) }
    $text = ($edits | ForEach-Object { "$($_.old_string)`n$($_.new_string)" }) -join "`n"
    $touchesTunable = [bool]($tunableNames | Where-Object { $text -match "\`$$_\b" })
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
