Describe 'B harmless native children (separate execution allowlist)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'FixtureSafety.ps1')
        Assert-DefinitionSource (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        function New-Item {[CmdletBinding()]param($Path,$ItemType,[switch]$Force)throw 'Forbidden filesystem'}
        function Set-Acl {[CmdletBinding()]param($LiteralPath,$AclObject)throw 'Forbidden ACL'}
        function Start-Process {[CmdletBinding()]param($FilePath)throw 'Forbidden process'}
        . (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        $script:harmlessEngine=if($PSVersionTable.PSEdition -eq 'Desktop'){Join-Path $PSHOME 'powershell.exe'}else{Join-Path $PSHOME 'pwsh.exe'}
        $script:echoBody=@'
$ErrorActionPreference='Stop'
if($args[0] -eq 'stderr'){[Console]::Error.WriteLine('fixed harmless stderr')}
$items=[object[]]@($args | Select-Object -Skip 2)
[Console]::WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $items -Compress))))
exit ([int]$args[1])
'@
        $script:constantBody=@'
param([string]$Source,[string]$Safety)
. $Safety
Assert-DefinitionSource $Source
function New-Item {throw 'Forbidden filesystem'}
function Set-Acl {throw 'Forbidden ACL'}
function Start-Process {throw 'Forbidden process'}
. $Source
function Assert-NativeApproval {}
$script:leafCalls=0
function Invoke-NativeLeaf {$script:leafCalls++;throw 'Unexpected native launch'}
New-Variable LASTEXITCODE -Scope Global -Value 77 -Option Constant
try {$null=Invoke-NativeCommand 'C:\fixture\unused.exe' @('fixed');exit 2}
catch {if($global:LASTEXITCODE -ne 77 -or $script:leafCalls -ne 0){exit 3};[Console]::WriteLine('Constant refused before launch');exit 0}
'@
        $script:entryBody=@'
param([string]$Source,[string]$Safety,[string]$Status)
. $Safety
Assert-DefinitionSource $Source
function New-Item {throw 'Forbidden filesystem'}
function Set-Acl {throw 'Forbidden ACL'}
function Start-Process {throw 'Forbidden process'}
. $Source
if($Status -eq 'DefinitionsOnly'){[Console]::WriteLine('Caller survived definition load');exit 0}
function Main {[pscustomobject]@{Status=$Status;Failures=@();RecoveryStatus='NotEligible';State=@{}}}
Invoke-DirectEntry
'@
        $script:resetBody=@'
param([string]$Reset,[string]$Safety)
. $Safety
Assert-ResetDefinitionSource $Reset
& $Reset -MainScript 'C:\fixture\never-load.ps1'
exit $LASTEXITCODE
'@
        function Invoke-HarmlessFixtureNative {
            param([string]$ExecutablePath,[string[]]$Arguments)
            if($ExecutablePath -cne $harmlessEngine -or $Arguments.Count -lt 6 -or ($Arguments[0..4] -join '|') -cne '-NoProfile|-NonInteractive|-ExecutionPolicy|Bypass|-File'){throw 'Not harmless native allowlist'}
            $safe=Assert-FixturePath $Arguments[5]
            $body=Read-FixtureText $safe
            if($body -cne $echoBody -and $body -cne $constantBody -and $body -cne $entryBody -and $body -cne $resetBody){throw 'Unknown child body'}
            if($body -ceq $echoBody){if($Arguments.Count -lt 8 -or $Arguments[6] -notin 'echo','stderr' -or $Arguments[7] -notin '0','7','8','16'){throw 'Unknown echo mode/status'}}
            else {
                $expectedSource=if($body -ceq $resetBody){Join-Path $PSScriptRoot '..\reset-hpcc4.ps1'}else{Join-Path $PSScriptRoot '..\hpcc4-simple.ps1'}
                if($Arguments.Count -lt 8 -or $Arguments[6] -cne $expectedSource -or $Arguments[7] -cne (Join-Path $PSScriptRoot 'FixtureSafety.ps1')){throw 'Unknown child sources'}
                if($body -cne $entryBody -and $Arguments.Count -ne 8){throw 'Unexpected child arguments'}
                if($body -ceq $entryBody -and ($Arguments.Count -ne 9 -or $Arguments[8] -notin 'Succeeded','DryRun','Failed','Cancelled','DefinitionsOnly')){throw 'Unknown entry outcome'}
            }
            $script:harmlessChildCount++
            & $ExecutablePath @Arguments 2>&1
        }
        $script:harmlessChildCount=0
    }
    BeforeEach {
        $DryRun=$false;$Unlock=$false;$Cleanup=$false;$null=New-RunState
        Mock Get-LocalVolume {throw 'Forbidden volume'}
        Mock Get-RecoveryObject {throw 'Forbidden object/ACL'}
        Mock Get-CurrentWindowsIdentity {throw 'Forbidden identity'}
        Mock Set-RecoveryProtection {throw 'Forbidden ACL'}
        Mock Open-ProtectedRecoveryFile {throw 'Forbidden protected create'}
        Mock Get-RecoveryMachineId {throw 'Forbidden registry'}
        Mock Assert-NativeApproval {} # Test-only; production exposes no bypass.
        Mock Invoke-NativeLeaf {Invoke-HarmlessFixtureNative $ExecutablePath $Arguments}
        $script:childPath=Join-Path $TestDrive ([guid]::NewGuid().ToString()+'.ps1')
        Write-FixtureText $childPath $echoBody
        $script:fixedPrefix=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$childPath)
    }
    AfterAll {Write-Host "Harmless native child processes: $harmlessChildCount"}
    It 'real native argument <Label> is preserved' -ForEach @(@{Label='space';Argument='two words'},@{Label='Unicode';Argument='café 雪'},@{Label='trailing separator';Argument='C:\plain\'},@{Label='space path';Argument='C:\space dir\file.txt'}) {
        $r=Invoke-NativeCommand $harmlessEngine ($fixedPrefix+@('echo','0',$Argument));$r.ExitCode | Should -Be 0;$r.Output -is [object[]] | Should -BeTrue
        $json=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$r.Output[0]))
        $rows=@(ConvertFrom-Json $json);$rows.Count | Should -Be 1;$rows[0] | Should -Be $Argument
    }
    It 'whitespace path with trailing separator refuses before actual child launch' {
        $before=$harmlessChildCount
        {Invoke-NativeCommand $harmlessEngine ($fixedPrefix+@('echo','0','C:\space dir\'))} | Should -Throw
        $harmlessChildCount | Should -Be $before
    }
    It 'real stderr with zero status remains diagnostic under strict caller preferences' {
        $ErrorActionPreference='Stop';$PSNativeCommandUseErrorActionPreference=$true
        $r=Invoke-NativeCommand $harmlessEngine ($fixedPrefix+@('stderr','0','fixed'))
        $r.ExitCode | Should -Be 0;@($r.Output).Count | Should -BeGreaterThan 1;$ErrorActionPreference | Should -Be 'Stop';$PSNativeCommandUseErrorActionPreference | Should -BeTrue
    }
    It 'real exits <Code> follow the explicit success list' -ForEach @(@{Code='0';Codes=@(0);Ok=$true},@{Code='7';Codes=0..7;Ok=$true},@{Code='8';Codes=0..7;Ok=$false},@{Code='16';Codes=@(0);Ok=$false}) {
        if($Ok){(Invoke-NativeCommand $harmlessEngine ($fixedPrefix+@('echo',$Code,'fixed')) $Codes).ExitCode | Should -Be ([int]$Code)}else{{Invoke-NativeCommand $harmlessEngine ($fixedPrefix+@('echo',$Code,'fixed')) $Codes} | Should -Throw}
    }
    It 'constant global status refuses before launch in a disposable child' {
        Write-FixtureText $childPath $constantBody
        $r=Invoke-NativeCommand $harmlessEngine ($fixedPrefix+@((Join-Path $PSScriptRoot '..\hpcc4-simple.ps1'),(Join-Path $PSScriptRoot 'FixtureSafety.ps1')))
        $r.ExitCode | Should -Be 0;$r.Output | Should -Contain 'Constant refused before launch'
    }
    It 'direct reset refuses with process status one before legacy or arbitrary source work' {
        Write-FixtureText $childPath $resetBody
        $r=Invoke-NativeCommand $harmlessEngine ($fixedPrefix+@((Join-Path $PSScriptRoot '..\reset-hpcc4.ps1'),(Join-Path $PSScriptRoot 'FixtureSafety.ps1'))) @(1)
        $r.ExitCode | Should -Be 1;($r.Output -join ' ') | Should -Match 'Reset refused or incomplete'
    }
    It 'direct entry <Status> exits <Code> without production stages' -ForEach @(@{Status='Succeeded';Code=0},@{Status='DryRun';Code=0},@{Status='Failed';Code=1},@{Status='Cancelled';Code=1},@{Status='DefinitionsOnly';Code=0}) {
        Write-FixtureText $childPath $entryBody
        $r=Invoke-NativeCommand $harmlessEngine ($fixedPrefix+@((Join-Path $PSScriptRoot '..\hpcc4-simple.ps1'),(Join-Path $PSScriptRoot 'FixtureSafety.ps1'),$Status)) @($Code)
        $r.ExitCode | Should -Be $Code
        if($Status -eq 'DefinitionsOnly'){$r.Output | Should -Contain 'Caller survived definition load'}
    }
}
