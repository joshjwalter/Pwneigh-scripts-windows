# VM/operator companion. Restore only captured supported resources and retain
# all originals. Passwords, deleted accounts and blanket GPO rollback are unavailable.
param([string]$MainScript='')
function Invoke-Hpcc4Reset {
    param([string]$MainScript)
    $script:ResetFailure=$null
    try {
        if(-not $MainScript){$MainScript=Join-Path $PSScriptRoot 'hpcc4-simple.ps1'}
        $path=[IO.Path]::GetFullPath($MainScript)
        $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
        if($errors.Count -or $ast.Extent.Text -notmatch '(?m)^# HPCC4-SIMPLE-SCRIPT v1 ' -or $ast.EndBlock.Statements[-1].Extent.Text -ne 'if ($MyInvocation.InvocationName -ne ''.'') { Invoke-DirectEntry }'){throw 'Unsupported source/guard'}
        foreach($statement in $ast.EndBlock.Statements | Select-Object -SkipLast 1){
            if($statement -is [Management.Automation.Language.FunctionDefinitionAst]){continue}
            if($statement -isnot [Management.Automation.Language.AssignmentStatementAst]){throw 'Unsupported source load'}
            if(@($statement.FindAll({param($n)$n -is [Management.Automation.Language.InvokeMemberExpressionAst]},$true)).Count){throw 'Source load CLR invocation refused'}
            $commands=@($statement.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true))
            if($commands.Count -and ($commands.Count -ne 1 -or $commands[0].GetCommandName() -ne 'New-RunState' -or $statement.Left.Extent.Text -ne '$null')){throw 'Source load action refused'}
        }
        # Operator-selected trusted original; compatibility is not authentication.
        . $path
        $script:Unlock=$true;$Unlock=$true;$DryRun=$false;$Cleanup=$false;$null=New-RunState
        Initialize-RunPreflight
        if(-not(Initialize-Setup)){throw 'Captured recovery storage unavailable'}
        $read=Read-RecoveryRecords $OutDir
        if($read.Status -notin 'Complete','Absent'){throw 'Recovery metadata incomplete'}
        if((Read-Host 'Restore captured ACL/registry resources only? Type RESET') -cne 'RESET'){return 0}
        foreach($record in @($read.Items | Where-Object State -ne 'Restored')){
            switch($record.Kind){
                Acl {$null=Restore-AclRecoveryRecord $record}
                Registry {$null=Restore-OwnedRegistryRecord $record}
                Tool {Add-RunFailure 'Reset' 'Tool' 'Service/configuration rollback requires manual verification; no uninstall attempted'}
                default {Write-Log "Retained $($record.Kind) evidence; no supported automatic restore for this resource."}
            }
        }
        Write-Log 'Originals retained. Passwords/deleted SIDs and blanket firewall/GPO policy are not automatically restored.'
        if($State.Failures.Count){return 1};return 0
    }catch{
        $script:ResetFailure=[pscustomobject]@{Stage='Reset';Operation='CheckedRestore';Detail=$_.Exception.GetType().Name}
        Write-Host 'Reset refused or incomplete; preserve recovery inputs and inspect the failure.'
        return 1
    }finally{if(Get-Command Close-RecoverySession -CommandType Function -ErrorAction SilentlyContinue){Close-RecoverySession}}
}
if ($MyInvocation.InvocationName -ne '.') { exit (Invoke-Hpcc4Reset $MainScript) }
