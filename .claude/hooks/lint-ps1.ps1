function Get-Hpcc4LintResult {
    param([string]$Path)
    if(-not $Path -or [IO.Path]::GetExtension($Path) -ine '.ps1'){return @{Status='Clean'}}
    try{
        if(-not(Test-Path -LiteralPath $Path)){throw 'File unavailable'}
        if(-not(Get-Module -ListAvailable PSScriptAnalyzer)){return @{Status='Skipped';Message='PSScriptAnalyzer unavailable; lint SKIPPED.'}}
        $results=@(Invoke-ScriptAnalyzer -Path $Path -Severity Warning,Error -ErrorAction Stop)
        if(-not $results.Count){return @{Status='Clean'}}
        return @{Status='Findings';Message=($results | ForEach-Object {"[$($_.Severity)] line $($_.Line): $($_.RuleName) - $($_.Message)"}) -join "`n"}
    }catch{return @{Status='Failed';Message='Lint FAILED; analysis did not complete.'}}
}
if ($MyInvocation.InvocationName -ne '.') {
    try{$inputData=[Console]::In.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop;$result=Get-Hpcc4LintResult $inputData.tool_input.file_path}catch{$result=@{Status='Failed';Message='Lint FAILED: malformed hook input.'}}
    if($result.Status -ne 'Clean'){@{Status=$result.Status;hookSpecificOutput=@{hookEventName='PostToolUse';additionalContext=$result.Message}} | ConvertTo-Json -Depth 6 -Compress}
}
