Describe 'B cancellation and legacy reset boundary (no host mutation)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'FixtureSafety.ps1')
        Assert-DefinitionSource (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        Assert-ResetDefinitionSource (Join-Path $PSScriptRoot '..\reset-hpcc4.ps1')
        function New-Item {throw 'Forbidden filesystem'}
        function Set-Acl {throw 'Forbidden ACL'}
        function Start-Process {throw 'Forbidden process'}
        . (Join-Path $PSScriptRoot '..\reset-hpcc4.ps1')
        function Close-RecoverySession {}
        $script:stopBody=@'
param($Source,$Safety,$Entered,$Release,$Observed)
. $Safety
Assert-DefinitionSource $Source
function New-Item {throw 'Forbidden filesystem'}
function Set-Acl {throw 'Forbidden ACL'}
function Start-Process {throw 'Forbidden process'}
. $Source
$DryRun=$false;$Unlock=$false;$Cleanup=$true;$AvInstallerUrl=''
function Initialize-RunPreflight {$script:State.Preconditions.RecoveryEligible=$true;$script:State.Preconditions.RecoveryPlan.RuleOperations=@(@{Label='Keep';Proto='TCP';Port=22})}
function Initialize-Setup {$true}
function Initialize-DeploymentIdentity {}
function Backup-Targets {}
function Set-FirewallLockdown {}
function Remove-UnauthorizedUsers {}
function Set-LocalPasswords {$null=$Entered.Set();$null=$Release.WaitOne(5000)}
function Disable-ExtraServices {$Observed.Later++}
function Get-PersistenceReport {$Observed.Later++}
function Install-DodGpo {$Observed.Later++}
function Install-Tools {$Observed.Later++}
function Lock-Paths {$Observed.Later++}
function Add-Rule {$Observed.Recovery++}
function Invoke-Cleanup {$Observed.Cleanup++}
function Write-Summary {$Observed.Summary++}
function Write-Log {}
function Close-RecoverySession {$script:RecoveryContext=$null}
function Invoke-NativeLeaf {throw 'Forbidden native'}
function Start-InstallerLeaf {throw 'Forbidden installer'}
Main
'@
    }
    It 'reset refuses before arbitrary MainScript loading or legacy restore' {
        $script:ResetFailure=$null
        $path=Join-Path $TestDrive 'arbitrary-main.ps1'
        Write-FixtureText $path "throw 'Arbitrary source must never load'"
        $r=@(Invoke-Hpcc4Reset $path);$r.Count | Should -Be 1;$r[0] | Should -Be 1
        $ResetFailure.Stage | Should -Be 'Reset';$ResetFailure.Operation | Should -Be 'CheckedRestore'
    }
    It 'stopped runspace remains non-success and starts no later ordinary or cleanup work' {
        $source=Join-Path $PSScriptRoot '..\hpcc4-simple.ps1';$safety=Join-Path $PSScriptRoot 'FixtureSafety.ps1'
        Assert-DefinitionSource $source
        $entered=[Threading.ManualResetEvent]::new($false);$release=[Threading.ManualResetEvent]::new($false)
        $observed=[hashtable]::Synchronized(@{Later=0;Cleanup=0;Recovery=0;Summary=0})
        $worker=[PowerShell]::Create()
        try {
            $null=$worker.AddScript($stopBody).AddArgument($source).AddArgument($safety).AddArgument($entered).AddArgument($release).AddArgument($observed)
            $pending=$worker.BeginInvoke()
            $entered.WaitOne(5000) | Should -BeTrue
            $worker.Stop()
            $worker.InvocationStateInfo.State.ToString() | Should -Be 'Stopped'
            $observed.Later | Should -Be 0;$observed.Cleanup | Should -Be 0
            try {$rows=@($worker.EndInvoke($pending));@($rows | Where-Object Status -eq 'Succeeded').Count | Should -Be 0} catch [Management.Automation.PipelineStoppedException] {}
        } finally {$null=$release.Set();$worker.Dispose();$entered.Dispose();$release.Dispose()}
    }
}
