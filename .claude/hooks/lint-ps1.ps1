$ErrorActionPreference = 'Stop'
$input_ = [Console]::In.ReadToEnd() | ConvertFrom-Json
$filePath = $input_.tool_input.file_path
if (-not $filePath -or $filePath -notlike '*.ps1') { exit 0 }
if (-not (Test-Path $filePath)) { exit 0 }
if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) { exit 0 }

$results = Invoke-ScriptAnalyzer -Path $filePath -Severity Warning, Error
if (-not $results) { exit 0 }

$lines = $results | ForEach-Object { "  [$($_.Severity)] line $($_.Line): $($_.RuleName) - $($_.Message)" }
$output = @{
    hookSpecificOutput = @{
        hookEventName     = 'PostToolUse'
        additionalContext = "PSScriptAnalyzer findings for $(Split-Path $filePath -Leaf):`n$($lines -join "`n")"
    }
} | ConvertTo-Json -Depth 5 -Compress
Write-Output $output
exit 0
