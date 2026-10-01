# Pester is intentionally not installed here. Install exactly 5.9.1 first.
[CmdletBinding()]
param([string[]]$Path, [string]$ResultDirectory)
# PS5.1 evaluates automatic variables too early in script parameter defaults.
if (-not $PSBoundParameters.ContainsKey('Path')) { $Path = @($PSScriptRoot) }

function Invoke-Hpcc4Tests {
    [CmdletBinding()]
    param([string[]]$Path, [string]$ResultDirectory)
    if (-not $PSBoundParameters.ContainsKey('Path')) { $Path = @($PSScriptRoot) }
    $flagExisted = Test-Path Env:\HPCC4_PESTER_RUNNING
    $priorFlag = $env:HPCC4_PESTER_RUNNING
    $priorTls = [Net.ServicePointManager]::SecurityProtocol
    $exitExisted = $null -ne (Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue)
    $priorExit = $global:LASTEXITCODE
    $exitCode = 1
    $summary = $null
    try {
        $env:HPCC4_PESTER_RUNNING = '1'
        Import-Module -Name Pester -RequiredVersion 5.9.1 -ErrorAction Stop
        Write-Host "Engine: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion); Pester: $((Get-Module Pester).Version)"
        $configuration = New-PesterConfiguration
        $configuration.Run.Path = $Path
        $configuration.Run.PassThru = $true
        $configuration.Run.Exit = $false
        $configuration.Output.Verbosity = 'Detailed'
        $result = Invoke-Pester -Configuration $configuration -ErrorAction Stop
        if ($null -eq $result) { throw 'No Pester result' }
        $counts = @('TotalCount', 'PassedCount', 'FailedCount', 'FailedContainersCount', 'FailedBlocksCount', 'SkippedCount', 'NotRunCount', 'InconclusiveCount')
        foreach ($count in $counts) {
            if ($null -eq $result.$count -or $result.$count -isnot [int] -or $result.$count -lt 0) { throw 'Invalid Pester result counts' }
        }
        $summary = [ordered]@{
            Engine = $PSVersionTable.PSVersion.ToString(); Edition = $PSVersionTable.PSEdition
            Pester = (Get-Module Pester).Version.ToString()
            Total = $result.TotalCount; Passed = $result.PassedCount; Failed = $result.FailedCount
            FailedContainers = $result.FailedContainersCount; FailedBlocks = $result.FailedBlocksCount
            Skipped = $result.SkippedCount; NotRun = $result.NotRunCount; Inconclusive = $result.InconclusiveCount
            DurationSeconds = $result.Duration.TotalSeconds
        }
        if ($result.TotalCount -gt 0 -and $result.PassedCount -eq $result.TotalCount -and
            $result.FailedCount -eq 0 -and $result.FailedContainersCount -eq 0 -and $result.FailedBlocksCount -eq 0 -and
            $result.SkippedCount -eq 0 -and $result.NotRunCount -eq 0 -and $result.InconclusiveCount -eq 0) { $exitCode = 0 }
        if ($ResultDirectory) {
            $null = New-Item -ItemType Directory -Path $ResultDirectory -Force -ErrorAction Stop
            $summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ResultDirectory 'summary.json') -Encoding UTF8 -ErrorAction Stop
        }
    } catch {
        # Avoid publishing local usernames/absolute paths from infrastructure errors.
        Write-Host 'Test infrastructure failed; inspect local detailed output.'
        $exitCode = 1
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $priorTls
        if ($exitExisted) { $global:LASTEXITCODE = $priorExit }
        else { Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
        if ($flagExisted) { $env:HPCC4_PESTER_RUNNING = $priorFlag }
        else { Remove-Item Env:\HPCC4_PESTER_RUNNING -ErrorAction SilentlyContinue }
    }
    [pscustomobject]@{ ExitCode = $exitCode; Summary = $summary }
}

if ($MyInvocation.InvocationName -ne '.') {
    $decision = Invoke-Hpcc4Tests -Path $Path -ResultDirectory $ResultDirectory
    exit $decision.ExitCode
}
