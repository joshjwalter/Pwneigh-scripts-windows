$ErrorActionPreference = 'Stop'
$input_ = [Console]::In.ReadToEnd() | ConvertFrom-Json
$filePath = $input_.tool_input.file_path
if (-not $filePath -or $filePath -notlike '*.ps1') { exit 0 }
if (-not (Test-Path $filePath)) { exit 0 }

if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
    $ctx = "PSScriptAnalyzer is not installed - lint check for $(Split-Path $filePath -Leaf) was SKIPPED, not passed. Install it (Install-Module PSScriptAnalyzer) for real lint coverage."
} else {
    $results = Invoke-ScriptAnalyzer -Path $filePath -Severity Warning, Error
    if (-not $results) { exit 0 }
    $lines = $results | ForEach-Object { "  [$($_.Severity)] line $($_.Line): $($_.RuleName) - $($_.Message)" }
    $ctx = "PSScriptAnalyzer findings for $(Split-Path $filePath -Leaf):`n$($lines -join "`n")"
}
@{ hookSpecificOutput = @{ hookEventName = 'PostToolUse'; additionalContext = $ctx } } | ConvertTo-Json -Depth 5 -Compress
exit 0
