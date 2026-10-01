BeforeAll {
    $runnerPath = Join-Path $PSScriptRoot 'Invoke-Tests.ps1'
    . $runnerPath
    $runnerEngine = if ($PSVersionTable.PSEdition -eq 'Desktop') { Join-Path $PSHOME 'powershell.exe' } else { Join-Path $PSHOME 'pwsh.exe' }
    $originalFlagExists = Test-Path Env:\HPCC4_PESTER_RUNNING
    $originalFlag = $env:HPCC4_PESTER_RUNNING
    $originalExitExists = $null -ne (Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue)
    $originalExitValue = $global:LASTEXITCODE
    $originalTls = [Net.ServicePointManager]::SecurityProtocol
    function New-FakePesterResult {
        @{ TotalCount = 1; PassedCount = 1; FailedCount = 0; FailedContainersCount = 0; FailedBlocksCount = 0; SkippedCount = 0; NotRunCount = 0; InconclusiveCount = 0; Result = 'Passed'; Duration = [TimeSpan]::Zero }
    }
}
AfterAll {
    if ($originalFlagExists) { $env:HPCC4_PESTER_RUNNING = $originalFlag } else { Remove-Item Env:\HPCC4_PESTER_RUNNING -ErrorAction SilentlyContinue }
    if ($originalExitExists) { $global:LASTEXITCODE = $originalExitValue } else { Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
    [Net.ServicePointManager]::SecurityProtocol = $originalTls
}

Describe 'Pinned runner child process contract' {
    It 'selects its own directory when no path argument is supplied' {
        $fixtureRunner = Join-Path $TestDrive 'Invoke-Tests.ps1'
        [IO.File]::WriteAllBytes($fixtureRunner, [IO.File]::ReadAllBytes($runnerPath))
        [IO.File]::WriteAllText((Join-Path $TestDrive 'default.Tests.ps1'), "Describe 'default suite' { It 'passes' { 1 | Should -Be 1 } }", [Text.UTF8Encoding]::new($true))
        $childOutput = & $runnerEngine -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $fixtureRunner 2>&1
        $childExit = $LASTEXITCODE
        $childExit | Should -Be 0 -Because ($childOutput -join [Environment]::NewLine)
    }
    It '<Name> produces process exit <Expected>' -TestCases @(
        @{ Name = 'passing test'; Body = "Describe 'synthetic' { It 'passes' { 1 | Should -Be 1 } }"; Expected = 0 }
        @{ Name = 'failing test'; Body = "Describe 'synthetic' { It 'fails' { 1 | Should -Be 2 } }"; Expected = 1 }
        @{ Name = 'discovery throw'; Body = "throw 'synthetic discovery failure'"; Expected = 1 }
        @{ Name = 'parse failure'; Body = "Describe 'synthetic' {"; Expected = 1 }
        @{ Name = 'BeforeAll failure'; Body = "Describe 'synthetic' { BeforeAll { throw 'synthetic setup failure' }; It 'never executes' { } }"; Expected = 1 }
        @{ Name = 'BeforeEach failure'; Body = "Describe 'synthetic' { BeforeEach { throw 'synthetic block failure' }; It 'never executes' { } }"; Expected = 1 }
        @{ Name = 'zero discovered'; Body = '# synthetic empty suite'; Expected = 1 }
        @{ Name = 'skipped test'; Body = "Describe 'synthetic' { It 'skips' -Skip { } }"; Expected = 1 }
    ) {
        param($Name, $Body, $Expected)
        $fixture = Join-Path $TestDrive 'synthetic.Tests.ps1'
        [IO.File]::WriteAllText($fixture, $Body, [Text.UTF8Encoding]::new($true))
        $childOutput = & $runnerEngine -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $runnerPath -Path $fixture 2>&1
        $childExit = $LASTEXITCODE
        $childExit | Should -Be $Expected -Because ($childOutput -join [Environment]::NewLine)
    }
}

Describe 'Runner protected exit state in disposable children' {
    BeforeAll {
        $protectedChild = @'
param([string]$Runner, [string]$Option, [string]$Preference, [string]$FlagState, [switch]$DuringRun)
. $Runner
$ErrorActionPreference = $Preference
$ProgressPreference = 'SilentlyContinue'; $ConfirmPreference = 'None'; $WhatIfPreference = $false; $PSNativeCommandUseErrorActionPreference = $false
if ($FlagState -eq 'sentinel') { $env:HPCC4_PESTER_RUNNING = 'protected-sentinel' }
else { Remove-Item Env:\HPCC4_PESTER_RUNNING -ErrorAction SilentlyContinue }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::SystemDefault
$script:imports = 0; $script:invokes = 0
function Import-Module { [CmdletBinding()] param($Name, $RequiredVersion) $script:imports++ }
function Get-Module { param($Name) [pscustomobject]@{ Version = [version]'5.9.1' } }
function New-PesterConfiguration { @{ Run = @{}; Output = @{} } }
function Invoke-Pester {
    [CmdletBinding()] param($Configuration)
    $script:invokes++
    if ($DuringRun) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Remove-Variable LASTEXITCODE -Scope Global -ErrorAction Stop
        New-Variable LASTEXITCODE -Scope Global -Value 91 -Option $Option
    }
    @{ TotalCount = 1; PassedCount = 1; FailedCount = 0; FailedContainersCount = 0; FailedBlocksCount = 0; SkippedCount = 0; NotRunCount = 0; InconclusiveCount = 0; Duration = [TimeSpan]::Zero }
}
Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
if ($DuringRun) { New-Variable LASTEXITCODE -Scope Global -Value 77 }
else { New-Variable LASTEXITCODE -Scope Global -Value 77 -Option $Option }
$decision = $null; $failure = $null
try { $decision = Invoke-Hpcc4Tests -Path 'unused-harmless-fixture' } catch { $failure = $_.FullyQualifiedErrorId }
$exitVariable = Get-Variable LASTEXITCODE -Scope Global
[pscustomobject]@{
    Thrown = $failure; Decisions = @($decision).Count; DecisionExit = $decision.ExitCode
    Imports = $script:imports; Invokes = $script:invokes
    FlagExists = Test-Path Env:\HPCC4_PESTER_RUNNING; FlagValue = $env:HPCC4_PESTER_RUNNING
    ExitValue = $exitVariable.Value; ExitOptions = $exitVariable.Options.ToString()
    Tls = [Net.ServicePointManager]::SecurityProtocol.ToString(); Preference = $ErrorActionPreference.ToString()
    Progress = $ProgressPreference.ToString(); Confirm = $ConfirmPreference.ToString(); WhatIf = $WhatIfPreference; NativePreference = $PSNativeCommandUseErrorActionPreference
} | ConvertTo-Json -Compress
exit 0
'@
    }
    It 'refuses protected <Option> with <Preference> and flag <FlagState> before Pester' -TestCases @(
        foreach ($option in 'ReadOnly', 'Constant') {
            foreach ($preference in 'Stop', 'Continue') {
                foreach ($flagState in 'absent', 'sentinel') { @{ Option = $option; Preference = $preference; FlagState = $flagState } }
            }
        }
    ) {
        param($Option, $Preference, $FlagState)
        $child = Join-Path $TestDrive 'protected-child.ps1'
        [IO.File]::WriteAllText($child, $protectedChild, [Text.UTF8Encoding]::new($true))
        $childOutput = & $runnerEngine -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $child -Runner $runnerPath -Option $Option -Preference $Preference -FlagState $FlagState 2>&1
        $childExit = $LASTEXITCODE
        $childExit | Should -Be 0
        $observation = ($childOutput | Where-Object { "$_".StartsWith('{') } | Select-Object -Last 1) | ConvertFrom-Json
        $observation.Thrown | Should -BeNullOrEmpty
        $observation.Decisions | Should -Be 1
        $observation.DecisionExit | Should -Be 1
        $observation.Imports | Should -Be 0
        $observation.Invokes | Should -Be 0
        $observation.FlagExists | Should -Be ($FlagState -eq 'sentinel')
        if ($FlagState -eq 'sentinel') { $observation.FlagValue | Should -Be 'protected-sentinel' }
        $observation.ExitValue | Should -Be 77
        $observation.ExitOptions | Should -Be $Option
        $observation.Tls | Should -Be 'SystemDefault'
        $observation.Preference | Should -Be $Preference
        $observation.Progress | Should -Be 'SilentlyContinue'; $observation.Confirm | Should -Be 'None'
        $observation.WhatIf | Should -BeFalse; $observation.NativePreference | Should -BeFalse
    }
    It 'continues independent restoration when Pester introduces <Option> with <Preference>' -TestCases @(
        @{ Option = 'ReadOnly'; Preference = 'Stop' }, @{ Option = 'ReadOnly'; Preference = 'Continue' },
        @{ Option = 'Constant'; Preference = 'Stop' }, @{ Option = 'Constant'; Preference = 'Continue' }
    ) {
        param($Option, $Preference)
        $child = Join-Path $TestDrive 'protected-child.ps1'
        [IO.File]::WriteAllText($child, $protectedChild, [Text.UTF8Encoding]::new($true))
        $childOutput = & $runnerEngine -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $child -Runner $runnerPath -Option $Option -Preference $Preference -FlagState sentinel -DuringRun 2>&1
        $childExit = $LASTEXITCODE
        $childExit | Should -Be 0
        $observation = ($childOutput | Where-Object { "$_".StartsWith('{') } | Select-Object -Last 1) | ConvertFrom-Json
        $observation.Thrown | Should -BeNullOrEmpty
        $observation.Decisions | Should -Be 1
        $observation.DecisionExit | Should -Be 1
        $observation.Imports | Should -Be 1
        $observation.Invokes | Should -Be 1
        $observation.FlagExists | Should -BeTrue
        $observation.FlagValue | Should -Be 'protected-sentinel'
        $observation.ExitValue | Should -Be 91
        $observation.ExitOptions | Should -Be $Option
        $observation.Tls | Should -Be 'SystemDefault'
        $observation.Preference | Should -Be $Preference
        $observation.Progress | Should -Be 'SilentlyContinue'; $observation.Confirm | Should -Be 'None'
        $observation.WhatIf | Should -BeFalse; $observation.NativePreference | Should -BeFalse
    }
}

Describe 'Runner restores environment and refuses incomplete results in process' {
    BeforeEach {
        $script:fakeResult = New-FakePesterResult
        Mock Import-Module -ParameterFilter { $Name -eq 'Pester' } { }
        Mock Invoke-Pester { $script:fakeResult }
    }

    It 'restores <ExitState> exit state and TLS after <Outcome>' -TestCases @(
        @{ ExitState = 'absent'; Outcome = 'success' }, @{ ExitState = 'sentinel'; Outcome = 'success' },
        @{ ExitState = 'absent'; Outcome = 'throw' }, @{ ExitState = 'sentinel'; Outcome = 'throw' }
    ) {
        param($ExitState, $Outcome)
        if ($ExitState -eq 'absent') { Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
        else { $global:LASTEXITCODE = 77 }
        $tlsOriginal = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::SystemDefault
        $tlsBefore = [Net.ServicePointManager]::SecurityProtocol
        $preferencesBefore = @{ ErrorActionPreference = $ErrorActionPreference; ProgressPreference = $ProgressPreference; ConfirmPreference = $ConfirmPreference; WhatIfPreference = $WhatIfPreference; PSNativeCommandUseErrorActionPreference = $PSNativeCommandUseErrorActionPreference }
        Mock Invoke-Pester {
            $global:LASTEXITCODE = 91
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            if ($Outcome -eq 'throw') { throw 'synthetic process state fault' }
            $script:fakeResult
        }
        try {
            $decision = Invoke-Hpcc4Tests -Path 'unused-fixture.Tests.ps1'
            $decision.ExitCode | Should -Be $(if ($Outcome -eq 'success') { 0 } else { 1 })
            $exitAfter = Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
            ($null -ne $exitAfter) | Should -Be ($ExitState -eq 'sentinel')
            if ($ExitState -eq 'sentinel') { $exitAfter.Value | Should -Be 77 }
            [Net.ServicePointManager]::SecurityProtocol | Should -Be $tlsBefore
            foreach ($preference in $preferencesBefore.Keys) { (Get-Variable $preference -ValueOnly -ErrorAction SilentlyContinue) | Should -Be $preferencesBefore[$preference] }
        } finally {
            [Net.ServicePointManager]::SecurityProtocol = $tlsOriginal
        }
    }

    It 'restores <Initial> after <Stage>' -TestCases @(
        foreach ($initial in 'absent', 'sentinel') {
            foreach ($stage in 'success', 'invoke failure', 'import failure', 'report failure') {
                @{ Initial = $initial; Stage = $stage }
            }
        }
    ) {
        param($Initial, $Stage)
        if ($Initial -eq 'absent') { Remove-Item Env:\HPCC4_PESTER_RUNNING -ErrorAction SilentlyContinue }
        else { $env:HPCC4_PESTER_RUNNING = 'test-sentinel' }
        if ($Stage -eq 'invoke failure') { Mock Invoke-Pester { throw 'synthetic invoke fault' } }
        if ($Stage -eq 'import failure') { Mock Import-Module -ParameterFilter { $Name -eq 'Pester' } { throw 'synthetic import fault' } }
        if ($Stage -eq 'report failure') { Mock Set-Content { throw 'synthetic report fault' } }
        $decision = Invoke-Hpcc4Tests -Path 'unused-fixture.Tests.ps1' -ResultDirectory (Join-Path $TestDrive 'results')
        @($decision).Count | Should -Be 1
        $decision.ExitCode | Should -Be $(if ($Stage -eq 'success') { 0 } else { 1 })
        (Test-Path Env:\HPCC4_PESTER_RUNNING) | Should -Be ($Initial -eq 'sentinel')
        if ($Initial -eq 'sentinel') { $env:HPCC4_PESTER_RUNNING | Should -Be 'test-sentinel' }
    }

    It 'restores TLS independently after <Outcome>' -TestCases @(@{ Outcome = 'success' }, @{ Outcome = 'throw' }) {
        param($Outcome)
        $tlsOriginal = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::SystemDefault
        Mock Invoke-Pester {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            if ($Outcome -eq 'throw') { throw 'synthetic TLS fault' }
            $script:fakeResult
        }
        try {
            $null = Invoke-Hpcc4Tests -Path 'unused-fixture.Tests.ps1'
            [Net.ServicePointManager]::SecurityProtocol | Should -Be ([Net.SecurityProtocolType]::SystemDefault)
        } finally { [Net.ServicePointManager]::SecurityProtocol = $tlsOriginal }
    }

    It 'refuses result with <Property>' -TestCases @(
        @{ Property = 'FailedCount' }, @{ Property = 'FailedContainersCount' }, @{ Property = 'FailedBlocksCount' },
        @{ Property = 'SkippedCount' }, @{ Property = 'NotRunCount' }, @{ Property = 'InconclusiveCount' }
    ) {
        param($Property)
        $script:fakeResult[$Property] = 1
        (Invoke-Hpcc4Tests -Path 'unused-fixture.Tests.ps1').ExitCode | Should -Be 1
    }

    It 'refuses null result' {
        $script:fakeResult = $null
        (Invoke-Hpcc4Tests -Path 'unused-fixture.Tests.ps1').ExitCode | Should -Be 1
    }
    It 'refuses zero total' {
        $script:fakeResult.TotalCount = 0
        (Invoke-Hpcc4Tests -Path 'unused-fixture.Tests.ps1').ExitCode | Should -Be 1
    }
    It 'refuses malformed result instead of treating missing counts as zero' {
        $script:fakeResult = @{ TotalCount = 1; PassedCount = 1 }
        (Invoke-Hpcc4Tests -Path 'unused-fixture.Tests.ps1').ExitCode | Should -Be 1
    }
}
