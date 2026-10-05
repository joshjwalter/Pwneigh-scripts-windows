# Compare reconstructed old/proposed tunables and identity. Implementation-only
# edits keep the existing approval scope. No script text is evaluated.
function Get-Hpcc4EditDecision {
    param($InputObject,[string]$OriginalText)
    try{
        if($InputObject.tool_name -notin 'Edit','MultiEdit','Write'){return @{Status='Clean'}}
        $inputData=$InputObject.tool_input
        if(-not $inputData.file_path -or [IO.Path]::GetExtension($inputData.file_path) -ine '.ps1'){return @{Status='Clean'}}
        if(-not $PSBoundParameters.ContainsKey('OriginalText')){$OriginalText=if(Test-Path -LiteralPath $inputData.file_path){Get-Content -LiteralPath $inputData.file_path -Raw -ErrorAction Stop}else{''}}
        $proposed=$OriginalText
        if($InputObject.tool_name -eq 'Write'){$proposed=[string]$inputData.content}
        else{
            $edits=if($InputObject.tool_name -eq 'Edit'){@($inputData)}else{@($inputData.edits)}
            foreach($edit in $edits){
                $old=[string]$edit.old_string
                if(-not $old){throw 'Unsupported empty replacement'}
                $matches=[regex]::Matches($proposed,[regex]::Escape($old))
                if(-not $matches.Count -or ($matches.Count -ne 1 -and -not $edit.replace_all)){throw 'Replacement mismatch/ambiguity'}
                $proposed=$proposed.Replace($old,[string]$edit.new_string)
            }
        }
        $marker='# HPCC4-SIMPLE-SCRIPT v1'
        if(-not $OriginalText.Contains($marker) -and -not $proposed.Contains($marker)){return @{Status='Clean'}}
        $tunables='KeepOpenTcp','AllowTcp','AllowUdp','BlockTcp','BlockUdp','ExcludeUsers','AuthorizedUsers','ToolsDir','ToolsZip','ToolsZipSha256','AvInstallerUrl','AvInstallerExpectedSigner','InstallSysmon','BackupPaths','LockPaths','OutDir','DisableServices','DodGpoDir','DodGpoSelection','LgpoExe'
        $snapshots=@()
        foreach($text in @($OriginalText,$proposed)){
            $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$t,[ref]$e)
            if($e.Count){throw 'Unsupported malformed edit'}
            $values=@{}
            foreach($statement in $ast.EndBlock.Statements){if($statement -is [Management.Automation.Language.AssignmentStatementAst]){$name=$statement.Left.Extent.Text.TrimStart('$');if($name -in $tunables){if($values.ContainsKey($name)){throw 'Ambiguous tunable'};$values[$name]=$statement.Right.Extent.Text}}}
            $markerLines=@($text -split '\r?\n' | Where-Object {$_.Contains($marker)})
            $snapshots+=@{Values=$values;Marker=($markerLines -join "`n");Guard=$ast.EndBlock.Statements[-1].Extent.Text}
        }
        $changed=@()
        foreach($name in $tunables){if($snapshots[0].Values[$name] -cne $snapshots[1].Values[$name]){$changed+=$name}}
        if($snapshots[0].Marker -cne $snapshots[1].Marker){$changed+='IdentityMarker'}
        if($snapshots[0].Guard -cne $snapshots[1].Guard){$changed+='EntryGuard'}
        if(-not $changed.Count){return @{Status='Clean'}}
        return @{Status='Review';Changed=$changed;hookSpecificOutput=@{hookEventName='PreToolUse';permissionDecision='ask';permissionDecisionReason=('Review HPCC4 operator configuration/identity changes: '+($changed -join ', '))}}
    }catch{return @{Status='Unsupported';hookSpecificOutput=@{hookEventName='PreToolUse';additionalContext='HPCC4 edit reconstruction failed; no scope decision was made.'}}}
}
if ($MyInvocation.InvocationName -ne '.') {
    try{$decision=Get-Hpcc4EditDecision ([Console]::In.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop)}catch{$decision=@{Status='Unsupported';hookSpecificOutput=@{hookEventName='PreToolUse';additionalContext='Malformed hook input; no scope decision made.'}}}
    if($decision.Status -ne 'Clean'){$decision | ConvertTo-Json -Depth 8 -Compress}
}
