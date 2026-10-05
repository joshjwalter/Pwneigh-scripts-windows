Describe 'Watcher and development hook interfaces' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'FixtureSafety.ps1')
        Assert-DefinitionSource (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        . (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        . (Join-Path $PSScriptRoot '..\watch-hpcc4.ps1')
        . (Join-Path $PSScriptRoot '..\.claude\hooks\check-tunables-edit.ps1')
        . (Join-Path $PSScriptRoot '..\.claude\hooks\lint-ps1.ps1')
        function Invoke-ScriptAnalyzer {[CmdletBinding()]param($Path,$Severity)throw 'Denied analyzer leaf'}
        function Get-LocalUser {[CmdletBinding()]param()throw 'Denied users'}
        function Get-CimInstance {[CmdletBinding()]param($ClassName)throw 'Denied CIM'}
        function Get-ScheduledTask {[CmdletBinding()]param()throw 'Denied tasks'}
        function New-Observation {param($Rows,$Status='Complete');[pscustomobject]@{Status=$Status;Items=[object[]]@($Rows);Errors=@();ObservedAtUtc='2026-10-04T00:00:00Z'}}
        function New-Snapshot {param($Rows,$Status='Complete');[pscustomobject]@{ObservedAtUtc='2026-10-04T00:00:00Z';Categories=@{Users=(New-Observation $Rows $Status)}}}
        $script:hookOriginal="# HPCC4-SIMPLE-SCRIPT v1 - fixture`nparam()`n`$KeepOpenTcp = @(22)`nfunction Example { 'old' }`nif (`$MyInvocation.InvocationName -ne '.') { Invoke-DirectEntry }"
    }
    BeforeEach {
        Mock Get-LocalUser {@()};Mock Get-CimInstance {@()};Mock Get-ScheduledTask {@()}
        Mock Get-FirewallSnapshot {New-ReadResult 'Complete' @([pscustomobject]@{Profiles=@();Rules=@()})}
        Mock Get-RawRegistryValue {@{KeyExists=$false;Exists=$false;Kind='None';Value=$null}}
        Mock Get-CFileObservation {@{Attributes=0;Sddl='fixture';Identity=@{Policy='VolumeFileId';Value='fixture'}}}
        Mock Get-ListeningPorts {New-ReadResult 'Complete'}
        Mock Test-Path {$false};Mock Get-Item {throw 'Denied item read'};Mock Get-CanonicalFilePath {$Path};Mock Get-NativeFileDigest {throw 'Denied hash read'}
        $LockPaths=@();$OutDir='C:\fixture\out';$ToolsDir='C:\fixture\tools'
    }
    It 'SID identity represents a rename as a change rather than deletion/addition' {
        $before=New-Snapshot @(@{Key='SID1';Value=@{Name='old';Enabled=$true}})
        $after=New-Snapshot @(@{Key='SID1';Value=@{Name='new';Enabled=$true}})
        $changes=@(Compare-Snapshots $before $after);$changes.Count | Should -Be 1;$changes[0].Kind | Should -Be Changed
    }
    It 'failed reads are gaps and the next good read compares with the last good state' {
        $before=New-Snapshot @(@{Key='SID1';Value=$true});$good=@{Users=$before.Categories.Users}
        $gap=New-Snapshot @() Failed;$changes=@(Compare-Snapshots $before $gap $good);$changes[0].Kind | Should -Be Gap
        $good.Users.Items.Count | Should -Be 1
        $after=New-Snapshot @(@{Key='SID1';Value=$false});$changes=@(Compare-Snapshots $gap $after $good);$changes[0].Kind | Should -Be Changed
    }
    It 'typed false and the string False remain distinct' {$a=New-Snapshot @(@{Key='SID1';Value=$false});$b=New-Snapshot @(@{Key='SID1';Value='False'});@(Compare-Snapshots $a $b).Count | Should -Be 1}
    It 'default empty hash selection performs zero hash reads' {$snapshot=Get-Snapshot;$snapshot.Categories.CriticalHashes.Status | Should -Be Complete;Should -Invoke Get-NativeFileDigest -Times 0}
    It 'opted-in hashes exceeding the budget report incomplete coverage' {Mock Get-Item {[pscustomobject]@{PSIsContainer=$false;Attributes=0;Length=1024}};$snapshot=Get-Snapshot @('C:\fixture\large') 1;$snapshot.Categories.CriticalHashes.Status | Should -Be Failed;Should -Invoke Get-NativeFileDigest -Times 0}
    It 'invalid polling intervals are rejected before source loading' {{Invoke-Hpcc4Watch -MainScript 'C:\never-load.ps1' -IntervalSeconds 0} | Should -Throw}
    It 'implementation-only edits keep the approval scope unchanged' {$inputData=@{tool_name='Edit';tool_input=@{file_path='C:\fixture.ps1';old_string="'old'";new_string="'new'"}};(Get-Hpcc4EditDecision $inputData $hookOriginal).Status | Should -Be Clean}
    It 'a replacement of only the tunable RHS still requests review' {$inputData=@{tool_name='Edit';tool_input=@{file_path='C:\fixture.ps1';old_string='@(22)';new_string='@(23)'}};$decision=Get-Hpcc4EditDecision $inputData $hookOriginal;$decision.Status | Should -Be Review;$decision.Changed | Should -Contain KeepOpenTcp}
    It 'a full-file implementation rewrite does not broaden review' {$inputData=@{tool_name='Write';tool_input=@{file_path='C:\fixture.ps1';content=$hookOriginal.Replace("'old'","'new'")}};(Get-Hpcc4EditDecision $inputData $hookOriginal).Status | Should -Be Clean}
    It 'marker removal and changed guard are reviewed using the old identity' {$inputData=@{tool_name='Write';tool_input=@{file_path='C:\fixture.ps1';content=$hookOriginal.Replace('HPCC4-SIMPLE-SCRIPT v1','removed-marker').Replace('Invoke-DirectEntry','Main')}};$decision=Get-Hpcc4EditDecision $inputData $hookOriginal;$decision.Changed | Should -Contain IdentityMarker;$decision.Changed | Should -Contain EntryGuard}
    It 'unsupported replacement reconstruction is diagnostic without a new approval scope' {$inputData=@{tool_name='Edit';tool_input=@{file_path='C:\fixture.ps1';old_string='missing';new_string='x'}};$decision=Get-Hpcc4EditDecision $inputData $hookOriginal;$decision.Status | Should -Be Unsupported;$decision.hookSpecificOutput.permissionDecision | Should -BeNullOrEmpty}
    It 'lint skipped, failed and clean results are distinct' {
        Mock Test-Path {$true};Mock Get-Module {@()};(Get-Hpcc4LintResult 'C:\fixture.ps1').Status | Should -Be Skipped
        Mock Get-Module {@{Name='PSScriptAnalyzer'}};Mock Invoke-ScriptAnalyzer {throw 'analyzer fault'};(Get-Hpcc4LintResult 'C:\fixture.ps1').Status | Should -Be Failed
        Mock Invoke-ScriptAnalyzer {@()};(Get-Hpcc4LintResult 'C:\fixture.ps1').Status | Should -Be Clean
    }
}
