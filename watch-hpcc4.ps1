# Read-only polling companion. Uses the trusted original main script's final
# interfaces. Transient changes and same-metadata changes can be missed.
param([string]$MainScript='',[int]$IntervalSeconds=2,[int]$DurationSeconds=0,[string[]]$CriticalHashPaths=@(),[long]$HashByteBudget=67108864)
function Read-WatchCategory {
    param([scriptblock]$Action)
    try{
        $rows=@(& $Action);$seen=@{}
        foreach($row in $rows){if(-not $row.Key -or $seen.ContainsKey([string]$row.Key)){throw 'Ambiguous identity'};$seen[[string]$row.Key]=$true}
        [pscustomobject]@{Status='Complete';Items=[object[]]@($rows | Sort-Object Key);Errors=@();ObservedAtUtc=[datetime]::UtcNow.ToString('o')}
    }catch{[pscustomobject]@{Status='Failed';Items=[object[]]@();Errors=@('ObservationFailed');ObservedAtUtc=[datetime]::UtcNow.ToString('o')}}
}
function Get-Snapshot {
    param([string[]]$CriticalHashPaths=@(),[long]$HashByteBudget=67108864)
    $categories=[ordered]@{}
    $categories.Users=Read-WatchCategory {foreach($u in @(Get-LocalUser -ErrorAction Stop)){[pscustomobject]@{Key=[string]$u.SID;Value=@{Name=[string]$u.Name;Enabled=[bool]$u.Enabled;PasswordLastSet=$u.PasswordLastSet}}}}
    $categories.Firewall=Read-WatchCategory {
        $read=Get-FirewallSnapshot;if($read.Status -ne 'Complete'){throw 'Firewall incomplete'}
        foreach($p in $read.Items[0].Profiles){[pscustomobject]@{Key='Profile|'+$p.Name;Value=@{Enabled=[string]$p.Enabled;DefaultInboundAction=[string]$p.DefaultInboundAction;AllowLocalFirewallRules=[string]$p.AllowLocalFirewallRules}}}
        foreach($r in $read.Items[0].Rules){[pscustomobject]@{Key=$r.Source+'|'+$r.Name;Value=@{Enabled=$r.Enabled;Direction=$r.Direction;Action=$r.Action;Profile=$r.Profile;Port=$r.Port;Address=$r.Address;Application=$r.Application;Service=$r.Service;Interface=$r.Interface;Security=$r.Security}}}
    }
    $categories.Services=Read-WatchCategory {foreach($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)){[pscustomobject]@{Key=$s.Name;Value=@{State=$s.State;StartMode=$s.StartMode;PathName=$s.PathName;StartName=$s.StartName}}}}
    $categories.Tasks=Read-WatchCategory {foreach($t in @(Get-ScheduledTask -ErrorAction Stop)){[pscustomobject]@{Key=$t.TaskPath+$t.TaskName;Value=@{State=[string]$t.State;Principal=$t.Principal;Settings=$t.Settings;Triggers=@($t.Triggers);Actions=@($t.Actions)}}}}
    $categories.Registry=Read-WatchCategory {
        foreach($entry in @(@('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment','Path'),@('HKCU:\Software\Sysinternals','EulaAccepted'),@('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','UserAuthentication'),@('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential'))){[pscustomobject]@{Key=$entry -join '|';Value=(Get-RawRegistryValue $entry[0] $entry[1])}}
    }
    $categories.LockedPaths=Read-WatchCategory {foreach($p in $LockPaths){[pscustomobject]@{Key=$p;Value=(Get-CFileObservation $p)}}}
    $categories.Listeners=Read-WatchCategory {$read=Get-ListeningPorts;if($read.Status -ne 'Complete'){throw 'Listeners incomplete'};foreach($p in $read.Items){[pscustomobject]@{Key="$($p.Proto):$($p.Port)";Value=$p}}}
    $categories.Storage=Read-WatchCategory {
        foreach($path in @($OutDir,$ToolsDir)){
            if(Test-Path -LiteralPath $path){$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;[pscustomobject]@{Key=$path;Value=@{Exists=$true;Attributes=[int]$item.Attributes;LastWriteTimeUtc=$item.LastWriteTimeUtc}}}
            else{[pscustomobject]@{Key=$path;Value=@{Exists=$false}}}
        }
    }
    $remaining=$HashByteBudget
    $categories.CriticalHashes=Read-WatchCategory {
        if($CriticalHashPaths.Count -gt 32){throw 'Hash path limit'}
        foreach($path in $CriticalHashPaths){
            $path=Get-CanonicalFilePath $path -MustExist;$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if($item.PSIsContainer -or $item.Attributes -band 1024 -or $item.Length -gt 16777216 -or $item.Length -gt $remaining){throw 'Hash coverage incomplete/budget exceeded'}
            $remaining-=$item.Length
            [pscustomobject]@{Key=$path;Value=@{Length=[long]$item.Length;LastWriteTimeUtc=$item.LastWriteTimeUtc;Digest=(Get-NativeFileDigest $path)}}
        }
    }
    [pscustomobject]@{ObservedAtUtc=[datetime]::UtcNow.ToString('o');Categories=$categories}
}
function Compare-Snapshots {
    param($Before,$After,[hashtable]$LastGood=@{})
    $changes=@()
    foreach($name in $After.Categories.Keys){
        $current=$After.Categories[$name]
        if($current.Status -ne 'Complete'){$changes+=[pscustomobject]@{Category=$name;Kind='Gap';Key='';Before=$null;After=$current.Status;ObservedAtUtc=$current.ObservedAtUtc};continue}
        $prior=if($LastGood.ContainsKey($name)){$LastGood[$name]}else{$Before.Categories[$name]}
        if($prior -and $prior.Status -eq 'Complete'){
            $old=@{};$new=@{};foreach($row in $prior.Items){$old[$row.Key]=$row.Value};foreach($row in $current.Items){$new[$row.Key]=$row.Value}
            foreach($key in @(@($old.Keys)+@($new.Keys) | Sort-Object -Unique)){
                $kind=if(-not $old.ContainsKey($key)){'Added'}elseif(-not $new.ContainsKey($key)){'Removed'}elseif(-not(Test-DataEqual $old[$key] $new[$key])){'Changed'}else{''}
                if($kind){$changes+=[pscustomobject]@{Category=$name;Kind=$kind;Key=$key;Before=$old[$key];After=$new[$key];ObservedAtUtc=$current.ObservedAtUtc}}
            }
        }
        $LastGood[$name]=$current
    }
    return $changes
}
function Invoke-Hpcc4Watch {
    param([string]$MainScript,[int]$IntervalSeconds=2,[int]$DurationSeconds=0,[string[]]$CriticalHashPaths=@(),[long]$HashByteBudget=67108864)
    if($IntervalSeconds -lt 1 -or $IntervalSeconds -gt 3600 -or $DurationSeconds -lt 0 -or $DurationSeconds -gt 86400 -or $HashByteBudget -lt 0 -or $HashByteBudget -gt 268435456){throw 'Invalid polling/hash limits'}
    if(-not $MainScript){$MainScript=Join-Path $PSScriptRoot 'hpcc4-simple.ps1'}
    $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile([IO.Path]::GetFullPath($MainScript),[ref]$t,[ref]$e)
    if($e.Count -or $ast.Extent.Text -notmatch '(?m)^# HPCC4-SIMPLE-SCRIPT v1 ' -or $ast.EndBlock.Statements[-1].Extent.Text -ne 'if ($MyInvocation.InvocationName -ne ''.'') { Invoke-DirectEntry }'){throw 'Unsupported trusted original source'}
    foreach($statement in $ast.EndBlock.Statements | Select-Object -SkipLast 1){
        if($statement -is [Management.Automation.Language.FunctionDefinitionAst]){continue}
        if($statement -isnot [Management.Automation.Language.AssignmentStatementAst] -or @($statement.FindAll({param($n)$n -is [Management.Automation.Language.InvokeMemberExpressionAst]},$true)).Count){throw 'Unsupported source load'}
        $commands=@($statement.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true))
        if($commands.Count -and ($commands.Count -ne 1 -or $commands[0].GetCommandName() -ne 'New-RunState' -or $statement.Left.Extent.Text -ne '$null')){throw 'Unsupported source action'}
    }
    . $MainScript
    $first=Get-Snapshot $CriticalHashPaths $HashByteBudget;$previous=$first;$good=@{};$baselineGood=@{}
    foreach($name in $first.Categories.Keys){if($first.Categories[$name].Status -eq 'Complete'){$good[$name]=$first.Categories[$name];$baselineGood[$name]=$first.Categories[$name]}}
    $clock=[Diagnostics.Stopwatch]::StartNew();$final=$null
    try{
        while(-not $DurationSeconds -or $clock.Elapsed.TotalSeconds -lt $DurationSeconds){
            Start-Sleep -Seconds $IntervalSeconds;$current=Get-Snapshot $CriticalHashPaths $HashByteBudget
            Compare-Snapshots $previous $current $good | ForEach-Object {Write-Host (ConvertTo-Json -InputObject $_ -Compress -Depth 20)};$previous=$current
        }
    }finally{
        $final=Get-Snapshot $CriticalHashPaths $HashByteBudget
        Write-Host "Final observation at $($final.ObservedAtUtc); failed categories are gaps, last-good observations retain their own timestamp."
        Compare-Snapshots $first $final $baselineGood | ForEach-Object {Write-Host (ConvertTo-Json -InputObject $_ -Compress -Depth 20)}
        $clock.Stop()
    }
    [pscustomobject]@{First=$first;Final=$final;LastGood=$good}
}
if ($MyInvocation.InvocationName -ne '.') { Invoke-Hpcc4Watch $MainScript $IntervalSeconds $DurationSeconds $CriticalHashPaths $HashByteBudget }
