Describe 'Safety-isolated unit suite' {
BeforeAll {
    $savedTls = [Net.ServicePointManager]::SecurityProtocol
    $savedExit = Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    $savedExitValue = if ($null -ne $savedExit) { $savedExit.Value } else { $null }
    $savedFlagExists = Test-Path Env:\HPCC4_PESTER_RUNNING
    $savedFlag = $env:HPCC4_PESTER_RUNNING
    $savedPreferences = @{ ErrorActionPreference = $ErrorActionPreference; ProgressPreference = $ProgressPreference; ConfirmPreference = $ConfirmPreference; WhatIfPreference = $WhatIfPreference }
    $trustedCmd = Join-Path ([Environment]::GetFolderPath('System')) 'cmd.exe'
    if (-not (Test-Path -LiteralPath $trustedCmd)) { throw 'Trusted inbox cmd.exe required' }
    $tokens = $null; $parseErrors = $null
    $sourceAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\hpcc4-simple.ps1'), [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'Production parse failed' }
    # Preflight the entry guard before load; a changed guard must never select
    # Main on this host before per-test fixture controls are installed.
    $entryGuard = $sourceAst.EndBlock.Statements[-1]
    if ($entryGuard -isnot [Management.Automation.Language.IfStatementAst] -or $entryGuard.Clauses.Count -ne 1 -or
        $entryGuard.Clauses[0].Item1.Extent.Text -ne '$MyInvocation.InvocationName -ne ''.''' -or
        $entryGuard.Clauses[0].Item2.Statements.Count -ne 1 -or $entryGuard.Clauses[0].Item2.Statements[0].Extent.Text -ne 'Main' -or
        $null -ne $entryGuard.ElseClause) { throw 'Production dot-source entry guard changed; audit before execution' }
    # Literal appcmd/LGPO/Sysmon and .NET ClearLog cannot be intercepted.
    # Their branches remain unreachable. Throwing named defaults precede load.
    function Stop-Service { [CmdletBinding()] param($Name, [switch]$Force) throw 'Forbidden host mutation: service' }
    function Set-Service { [CmdletBinding()] param($Name, $StartupType) throw 'Forbidden host mutation: service' }
    function Invoke-WebRequest { [CmdletBinding()] param([Parameter(Position=0)]$Uri, $OutFile, [switch]$UseBasicParsing) throw 'Forbidden host mutation: download' }
    function Expand-Archive { [CmdletBinding()] param($Path, $DestinationPath, [switch]$Force) throw 'Forbidden host mutation: archive' }
    function Start-Process { [CmdletBinding()] param([Parameter(Position=0)]$FilePath) throw 'Forbidden host mutation: process' }
    function Set-ItemProperty { [CmdletBinding()] param([Parameter(Position=0)]$Path, $Name, $Value) throw 'Forbidden host mutation: registry' }
    function New-ItemProperty { [CmdletBinding()] param([Parameter(Position=0)]$Path, $Name, $Value, $PropertyType, [switch]$Force) throw 'Forbidden host mutation: registry' }
    function Clear-History { [CmdletBinding()] param() throw 'Forbidden host mutation: history' }
    function Set-PSReadLineOption { [CmdletBinding()] param($HistorySaveStyle) throw 'Forbidden host mutation: history options' }
    function gpupdate { throw 'Forbidden native: GPO' }
    # --- Stub cmdlets that don't exist on this box / this PS edition so
    # Pester can Mock them. Defined UNCONDITIONALLY so they shadow any real
    # cmdlet of the same name too (deliberate safety net on Windows).
    function Get-LocalUser { [CmdletBinding()] param([string]$Name) }
    function Set-LocalUser { [CmdletBinding()] param([string]$Name, [System.Security.SecureString]$Password) throw 'Forbidden host mutation: password' }
    function Remove-LocalUser { [CmdletBinding()] param($SID, [string]$Name) throw 'Forbidden host mutation: account' }
    function Get-LocalGroup { [CmdletBinding()] param() }
    function Get-LocalGroupMember { [CmdletBinding()] param([Parameter(Position = 0)]$Group) }
    function Get-CimInstance { [CmdletBinding()] param([string]$ClassName, [string]$Filter) }
    function Get-NetTCPConnection { [CmdletBinding()] param([string]$State) }
    function Get-NetUDPEndpoint { [CmdletBinding()] param() }
    function Get-NetFirewallRule { [CmdletBinding()] param([string[]]$Name, [string]$DisplayName, [string]$Direction, [string]$PolicyStore, [string]$Action, $Enabled) }
    function Get-NetFirewallPortFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$InputObject) }
    function New-NetFirewallRule { [CmdletBinding()] param([string]$Name, [string]$DisplayName, [string]$Direction, [string]$Protocol, $LocalPort, [string]$Action) throw 'Forbidden host mutation: firewall' }
    function Remove-NetFirewallRule { [CmdletBinding()] param([string[]]$Name, [string]$DisplayName) throw 'Forbidden host mutation: firewall' }
    function Set-NetFirewallProfile { [CmdletBinding()] param([string[]]$Profile, $Enabled, [string]$DefaultInboundAction) throw 'Forbidden host mutation: firewall' }
    function Get-ScheduledTask { [CmdletBinding()] param() }

    # --- Stub native/bare-name commands too, BEFORE mocking them, so nothing
    # real can ever run underneath a Mock.
    function netsh { throw 'Forbidden native: netsh' }
    function icacls { throw 'Forbidden native: icacls' }
    function robocopy { throw 'Forbidden native: robocopy' }
    function attrib { throw 'Forbidden native: attrib' }

    # --- Dot-source the script under test. Its last line is the invocation
    # guard, so dot-sourcing (InvocationName '.') runs nothing, including Main.
    . (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')

    # --- Shared helper: $State is a script-level hashtable the real script
    # mutates in place and never reassigns. Reset its keys between tests.
    function Reset-TestState {
        # A new caller-visible hashtable per setup prevents retained State
        # references (and its arrays) from leaking across tests.
        Set-Variable -Name State -Scope 1 -Value @{}
        $script:DryRun = $false; $script:Unlock = $false; $script:Cleanup = $false
        $script:OutDir = "$TestDrive\out"; $script:ToolsDir = "$TestDrive\tools"
        $script:KeepOpenTcp = @(22); $script:AllowTcp = @(); $script:AllowUdp = @(); $script:BlockTcp = @(); $script:BlockUdp = @()
        $script:ExcludeUsers = @(); $script:AuthorizedUsers = @(); $script:BackupPaths = @(); $script:LockPaths = @(); $script:DisableServices = @()
        $script:ToolsZip = ''; $script:ToolsZipSha256 = ''; $script:AvInstallerUrl = ''; $script:AvInstallerExpectedSigner = ''; $script:InstallSysmon = $false
        $script:DodGpoDir = ''; $script:LgpoExe = ''
        $State.Clear()
        $State.IsDC = $false
        $State.RdpPort = 3389
        $State.BackupDir = ''
        $State.Uncovered = @()
        $State.Purge = $false
        $State.Enable = $true
        $State.FirewallOn = $false
        $State.RulesAdded = @()
        $State.BlocksRefused = @()
        $State.Deleted = @()
        $State.Changed = @()
        $State.ToolsInstalled = $false
        $State.HashChecked = 'no'
        $State.AvInstaller = ''
        $State.Locked = @()
        $State.Failures = @()
        $State.ServicesDisabled = @(); $State.Persistence = @(); $State.GpoApplied = @()
    }
}

BeforeEach { Reset-TestState }
AfterAll {
    [Net.ServicePointManager]::SecurityProtocol = $savedTls
    if ($null -ne $savedExit) { $global:LASTEXITCODE = $savedExitValue } else { Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
    if ($savedFlagExists) { $env:HPCC4_PESTER_RUNNING = $savedFlag } else { Remove-Item Env:\HPCC4_PESTER_RUNNING -ErrorAction SilentlyContinue }
    foreach ($name in $savedPreferences.Keys) { Set-Variable -Name $name -Value $savedPreferences[$name] }
}

Describe 'Password target list' {
    BeforeEach {
        Reset-TestState
        $OutDir = "$TestDrive\out"
        $ExcludeUsers = @()
    }

    It 'removes ExcludeUsers from the target list' {
        Mock Get-LocalEnabledUsers { @('Admin', 'Bob', 'Scoring') }
        Mock Get-InUseAccounts { @() }
        $ExcludeUsers = @('Scoring')

        $result = Get-PasswordTargets

        $result | Should -Not -Contain 'Scoring'
        $result | Should -Contain 'Bob'
        $result | Should -Contain 'Admin'
    }

    It 'removes service, app pool, and task accounts, including .\ and HOST\ prefixed forms' {
        Mock Get-LocalEnabledUsers { @('Admin', 'svcacct', 'poolacct', 'taskacct', 'Bob') }
        # One of each source's forms: service '.\', app pool 'HOST\', task 'DOMAIN\' (different case too), plus a null entry.
        Mock Get-InUseAccounts { @('.\svcacct', "$env:COMPUTERNAME\poolacct", 'CORP\TASKACCT', $null) }

        $result = Get-PasswordTargets

        $result | Should -Not -Contain 'svcacct'
        $result | Should -Not -Contain 'poolacct'
        $result | Should -Not -Contain 'taskacct'
        $result | Should -Contain 'Admin'
        $result | Should -Contain 'Bob'
    }

    It 'skips the step entirely on a domain controller, touching neither Read-Host nor Set-LocalUser' {
        $State.IsDC = $true
        Mock Write-Log { }
        Mock Read-Host { 'y' }
        Mock Set-LocalUser { }
        Mock Get-LocalEnabledUsers { @('Admin') }
        Mock Get-InUseAccounts { @() }

        Set-LocalPasswords

        Should -Invoke Read-Host -Times 0
        Should -Invoke Set-LocalUser -Times 0
        Should -Invoke Write-Log -ParameterFilter { $Message -match 'domain controller' } -Times 1
    }
}

Describe 'Write-Log' {
    It 'prints to the terminal and writes no log file' {
        $OutDir = "$TestDrive\out"
        [System.IO.Directory]::CreateDirectory($OutDir) | Out-Null
        Mock Write-Host { }

        Write-Log 'hello'

        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'hello$' } -Times 1
        @(Get-ChildItem $OutDir).Count | Should -Be 0
    }
}

Describe 'Unauthorized account removal' {
    BeforeEach {
        Reset-TestState
        $DryRun = $false
        $OutDir = "$TestDrive\out"
        [System.IO.Directory]::CreateDirectory($OutDir) | Out-Null
        $AuthorizedUsers = @('scoreuser')
        $ExcludeUsers = @('ftpuser')
        # RIDs under 1000 are built-in; 1000+ are accounts someone created.
        $mk = { param($n, $rid) [pscustomobject]@{ Name = $n; SID = [pscustomobject]@{ Value = "S-1-5-21-1-2-3-$rid" } } }
        $script:users = @(
            (& $mk 'Administrator' 500), (& $mk 'Guest' 501), (& $mk 'DefaultAccount' 503),
            (& $mk $env:USERNAME 1001), (& $mk 'scoreuser' 1002), (& $mk 'ftpuser' 1003), (& $mk 'svcweb' 1004),
            (& $mk 'redteam' 1005), (& $mk 'backdoor' 1006))
        Mock Get-LocalUser { $script:users }
        Mock Get-InUseAccounts { @('.\svcweb') }
        Mock Get-LocalGroup { }
        Mock Remove-LocalUser { }
        Mock Write-Log { }
        Mock Read-Host { 'y' }
    }

    It 'deletes only unauthorized, non-built-in accounts, and records each one first' {
        Remove-UnauthorizedUsers

        Should -Invoke Remove-LocalUser -Times 2
        $State.Deleted | Should -Be @('redteam', 'backdoor')
        Should -Invoke Write-Log -ParameterFilter { $Message -match '^Deleting redteam \(SID S-1-5-21-1-2-3-1005' } -Times 1
        Test-Path (Join-Path $OutDir 'deleted-users.txt') | Should -BeFalse
    }

    It 'never deletes built-ins, you, authorized, excluded or in-use accounts' {
        Remove-UnauthorizedUsers

        foreach ($safe in 'Administrator', 'Guest', 'DefaultAccount', $env:USERNAME, 'scoreuser', 'ftpuser', 'svcweb') {
            $State.Deleted | Should -Not -Contain $safe
        }
    }

    It 'skips entirely when $AuthorizedUsers is empty' {
        $AuthorizedUsers = @()

        Remove-UnauthorizedUsers

        Should -Invoke Read-Host -Times 0
        Should -Invoke Remove-LocalUser -Times 0
    }

    It 'skips on a domain controller' {
        $State.IsDC = $true

        Remove-UnauthorizedUsers

        Should -Invoke Remove-LocalUser -Times 0
    }

    It 'deletes nothing if you answer anything but y' {
        Mock Read-Host { 'n' }

        Remove-UnauthorizedUsers

        Should -Invoke Remove-LocalUser -Times 0
    }
}

Describe 'Firewall lockdown and service ports' {
    BeforeEach {
        Reset-TestState
        $DryRun = $false
        $State.RdpPort = 3389
        $OutDir = "$TestDrive\out"
        [System.IO.Directory]::CreateDirectory($OutDir) | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $OutDir 'firewall-before.wfw'), 'backup')
        $KeepOpenTcp = @(22)
        $AllowTcp = @()
        $AllowUdp = @()
        $BlockTcp = @()
        $BlockUdp = @()
        $script:calls = @()
        $script:removed = @()

        Mock Write-Log { }
        Mock Get-ListeningPorts { @() }
        Mock Get-InboundAllowPorts { @() }
        # Listing inbound rules returns a mix of built-in, foreign, old HPCC4 and keep rules.
        Mock Get-NetFirewallRule -ParameterFilter { $Direction -eq 'Inbound' } {
            'CoreNet-DHCP-In', 'CoreNet-DHCPV6-In', 'FTP-In', 'HPCC4-Allow-TCP-80', 'HPCC4-Keep-TCP-3389', 'HPCC4-Keep-TCP-22' | ForEach-Object { [pscustomobject]@{ Name = $_ } }
        }
        Mock Get-NetFirewallRule { $null }   # existence check by -Name: the keep rule isn't there yet
        Mock New-NetFirewallRule { $script:calls += "New:$Name" }
        Mock Remove-NetFirewallRule { $script:calls += 'Remove'; $script:removed = $Name }
        Mock Set-NetFirewallProfile { }
        Mock Read-Host { 'y' }
    }

    It 'lockdown adds the RDP and SSH keep rules BEFORE removing anything, keeps DHCP, and blocks inbound by default' {
        Set-FirewallLockdown

        $script:calls | Should -Be @('New:HPCC4-Keep-TCP-3389', 'New:HPCC4-Keep-TCP-22', 'Remove')
        $script:removed | Should -Contain 'FTP-In'
        $script:removed | Should -Contain 'HPCC4-Allow-TCP-80'
        $script:removed | Should -Not -Contain 'CoreNet-DHCP-In'
        $script:removed | Should -Not -Contain 'CoreNet-DHCPV6-In'
        $script:removed | Should -Not -Contain 'HPCC4-Keep-TCP-3389'
        $script:removed | Should -Not -Contain 'HPCC4-Keep-TCP-22'
        Should -Invoke Set-NetFirewallProfile -ParameterFilter { $DefaultInboundAction -eq 'Block' } -Times 1
        $State.Purge | Should -BeTrue
    }

    It 'does not purge on a domain controller' {
        $State.IsDC = $true

        Set-FirewallLockdown

        Should -Invoke Remove-NetFirewallRule -Times 0
        Should -Invoke Set-NetFirewallProfile -Times 0
        Should -Invoke Write-Log -ParameterFilter { $Message -match 'domain controller' } -Times 1
    }

    It 'without backup preserves existing rules and applies default block with valid keep rules' {
        Remove-Item (Join-Path $OutDir 'firewall-before.wfw')

        Set-FirewallLockdown

        Should -Invoke Remove-NetFirewallRule -Times 0
        Should -Invoke Set-NetFirewallProfile -Times 1 -Exactly -ParameterFilter {
            @($Profile).Count -eq 3 -and $Profile -contains 'Domain' -and $Profile -contains 'Private' -and $Profile -contains 'Public' -and
            "$Enabled" -eq 'True' -and $DefaultInboundAction -eq 'Block'
        }
        foreach ($port in 3389, 22) {
            Should -Invoke New-NetFirewallRule -Times 1 -Exactly -ParameterFilter {
                $Name -eq "HPCC4-Keep-TCP-$port" -and $DisplayName -eq $Name -and $Direction -eq 'Inbound' -and
                $Protocol -eq 'TCP' -and $LocalPort -eq $port -and $Action -eq 'Allow'
            }
        }
        $State.Purge | Should -BeFalse
        $State.FirewallOn | Should -BeTrue
    }

    It 'warns on uncovered listening ports; on "n" nothing is purged or turned on, but rules are still added at the end' {
        Mock Get-ListeningPorts { @([pscustomobject]@{ Proto = 'TCP'; Port = 8080; Process = 'evil.exe' }) }
        Mock Read-Host { 'n' }
        $AllowTcp = @(80)

        Set-FirewallLockdown
        Open-ServicePorts

        Should -Invoke Write-Log -ParameterFilter { $Message -match 'this service will be blocked once the firewall is on' } -Times 1
        Should -Invoke Read-Host -Times 1
        Should -Invoke Set-NetFirewallProfile -Times 0
        $script:removed | Should -Contain 'HPCC4-Allow-TCP-80'   # only old HPCC4 rules are replaced
        $script:removed | Should -Not -Contain 'FTP-In'
        Should -Invoke New-NetFirewallRule -ParameterFilter { $Name -eq 'HPCC4-Allow-TCP-80' } -Times 1
    }

    It 'never blocks the RDP port, a keep-open port or an allowed port, and logs REFUSED block' {
        $State.Purge = $true
        $AllowTcp = @(80)
        $BlockTcp = @(3389, 22, 80, 23)

        Open-ServicePorts

        Should -Invoke New-NetFirewallRule -ParameterFilter { $Name -like 'HPCC4-Block-*' } -Times 1
        Should -Invoke New-NetFirewallRule -ParameterFilter { $Name -eq 'HPCC4-Block-TCP-23' } -Times 1
        Should -Invoke Write-Log -ParameterFilter { $Message -match 'REFUSED block' } -Times 3
    }

    It 'opens the service ports at the end after a lockdown, without re-adding keep ports or re-purging' {
        $State.Purge = $true
        $State.FirewallOn = $true
        $AllowTcp = @(3389, 22, 80)
        $AllowUdp = @(53)

        Open-ServicePorts

        $script:calls | Should -Be @('New:HPCC4-Allow-TCP-80', 'New:HPCC4-Allow-UDP-53')
        Should -Invoke Set-NetFirewallProfile -Times 0
    }

    It 'Main reopens the service ports even if a step in the middle throws' {
        Mock Test-IsAdmin { $true }
        Mock Initialize-Setup { }
        Mock Backup-Targets { }
        Mock Set-FirewallLockdown { }
        Mock Set-LocalPasswords { throw 'interrupted' }
        Mock Install-Tools { }
        Mock Lock-Paths { }
        Mock Open-ServicePorts { }
        Mock Write-Summary { }
        $Unlock = $false

        { Main } | Should -Throw

        Should -Invoke Open-ServicePorts -Times 1
        Should -Invoke Install-Tools -Times 0
    }
}

Describe '-DryRun makes zero changes' {
    BeforeEach {
        Reset-TestState
        $DryRun = $true
        $Unlock = $false
        $OutDir = "$TestDrive\out"
        $ToolsDir = "$TestDrive\tools"
        $BackupPaths = @("$TestDrive\backupsrc\hosts.txt")
        $LockPaths = @("$TestDrive\locksrc\hosts.txt")
        $AllowTcp = @(3389)
        $AllowUdp = @(53)
        $BlockTcp = @(23)
        $BlockUdp = @(69)
        $ExcludeUsers = @()
        $AuthorizedUsers = @('Bob')
        $ToolsZip = 'https://example.invalid/t.zip'
        $ToolsZipSha256 = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
        $InstallSysmon = $true

        Mock Test-IsAdmin { $true }
        Mock Get-ItemProperty { [pscustomobject]@{ PortNumber = 3389 } }
        Mock Get-CimInstance { [pscustomobject]@{ DomainRole = 3 } }
        Mock Get-ListeningPorts { @() }
        Mock Get-InboundAllowPorts { @() }
        Mock Get-LocalEnabledUsers { @('Bob') }
        Mock Get-InUseAccounts { @() }
        Mock Get-LocalUser { [pscustomobject]@{ Name = 'redteam'; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1005' } } }
        Mock Get-PersistenceReport { $State.Persistence = @() }
        Mock Test-EveryoneDeny { $false }

        Mock netsh { }
        Mock icacls { }
        Mock robocopy { }
        Mock attrib { }

        Mock New-NetFirewallRule { }
        Mock Remove-NetFirewallRule { }
        Mock Set-NetFirewallProfile { }
        Mock Set-LocalUser { }
        Mock Remove-LocalUser { }
        Mock Expand-Archive { }
        Mock Start-Process { }
        Mock Invoke-WebRequest { }
        Mock Get-Item { [pscustomobject]@{} | Add-Member -MemberType ScriptMethod -Name GetValue -Value { 'C:\Windows' } -PassThru }
        Mock New-Item { }
        Mock Copy-Item { }
        Mock Set-ItemProperty { }
        Mock New-ItemProperty { }
        Mock Rename-Item { }
        Mock Set-Content { }
        Mock Read-Host { }
        Mock Write-Log { }
    }

    It 'touches none of the state-changing commands when Main runs' {
        # Note: Sysmon64 is invoked via `& (Join-Path $ToolsDir 'Sysmon64.exe')`,
        # a call by literal path rather than by command name, so Pester's Mock
        # cannot intercept it -- this is a known, unfixable gap in mockability.
        # It is not exercised here anyway: dry-run's Invoke-Step never runs the
        # action scriptblock at all, so Sysmon64 is never actually invoked.
        Main

        Should -Invoke New-NetFirewallRule -Times 0
        Should -Invoke Remove-NetFirewallRule -Times 0
        Should -Invoke Set-NetFirewallProfile -Times 0
        Should -Invoke Set-LocalUser -Times 0
        Should -Invoke Remove-LocalUser -Times 0
        Should -Invoke Write-Log -ParameterFilter { $Message -match 'UNAUTHORIZED accounts to DELETE: redteam' } -Times 1
        Should -Invoke Expand-Archive -Times 0
        Should -Invoke Start-Process -Times 0
        Should -Invoke Invoke-WebRequest -Times 0
        Should -Invoke New-Item -Times 0
        Should -Invoke Copy-Item -Times 0
        Should -Invoke Set-ItemProperty -Times 0
        Should -Invoke New-ItemProperty -Times 0
        Should -Invoke Rename-Item -Times 0
        Should -Invoke Set-Content -Times 0
        Should -Invoke Read-Host -Times 0
        Should -Invoke netsh -Times 0
        Should -Invoke icacls -Times 0
        Should -Invoke robocopy -Times 0
        Should -Invoke attrib -Times 0
        Should -Invoke Write-Log -ParameterFilter { $Message -match '^WOULD:' }
    }

    It 'touches none of the state-changing commands when Main runs with -Unlock' {
        [System.IO.Directory]::CreateDirectory($OutDir) | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $OutDir 'acl-fake.txt'), 'fake-acl')
        [System.IO.File]::WriteAllText((Join-Path $OutDir 'acl-fake.path'), "$TestDrive\locksrc\hosts.txt")
        $Unlock = $true

        Main

        Should -Invoke icacls -Times 0
        Should -Invoke attrib -Times 0
        Should -Invoke Rename-Item -Times 0
        Should -Invoke Write-Log -ParameterFilter { $Message -match '^WOULD:' }
    }
}

Describe 'AV installer download' {
    BeforeEach {
        Reset-TestState
        $DryRun = $false
        $OutDir = "$TestDrive\out"
        $ToolsDir = "$TestDrive\tools"
        $ToolsZip = ''
        $InstallSysmon = $false
        $AvInstallerUrl = 'https://example.invalid/AV_Setup.exe'
        Mock Get-Item { [pscustomobject]@{} | Add-Member -MemberType ScriptMethod -Name GetValue -Value { 'C:\Windows' } -PassThru }
        # Every write is mocked: nothing touches this PC's PATH, HKCU or ACLs.
        Mock Write-Log { }
        Mock icacls { }
        Mock New-Item { }
        Mock New-ItemProperty { }
        Mock Invoke-WebRequest { }
    }

    It 'keeps a validly signed installer to open at the end' {
        Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Subject = 'CN=Vendor' } } }

        Install-Tools

        $State.AvInstaller | Should -Be (Join-Path $ToolsDir 'AV_Setup.exe')
    }

    It 'refuses to open an installer without a valid signature' {
        Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null } }

        Install-Tools

        $State.AvInstaller | Should -Be ''
        Should -Invoke Write-Log -ParameterFilter { $Message -match 'will NOT be opened' } -Times 1
    }

    It 'does not download the installer if ToolsDir could not be locked down' {
        Mock icacls { $global:LASTEXITCODE = 5 }

        Install-Tools

        Should -Invoke Invoke-WebRequest -Times 0
    }
}
Describe 'Cleanup (Invoke-Cleanup)' {
    BeforeAll {
        # Shadow the real cmd.exe with a stub for THIS Describe only, so the
        # self-delete can never run for real. The Invoke-Step tests in their
        # own Describe still use the real cmd.
        function cmd { throw 'Forbidden native: cleanup scheduling' }
        function Get-PSReadLineOption { [CmdletBinding()] param() }
        function Get-WinEvent { [CmdletBinding()] param([string[]]$ListLog) }
    }
    BeforeEach {
        Reset-TestState
        $DryRun = $false
        $OutDir = "$TestDrive\existing-out"; $ToolsDir = "$TestDrive\existing-tools"
        [IO.Directory]::CreateDirectory($OutDir) | Out-Null
        [IO.Directory]::CreateDirectory($ToolsDir) | Out-Null
        [IO.File]::WriteAllText((Join-Path $OutDir 'retained.txt'), 'retain')
        Mock Write-Log { }
        Mock cmd { }
        Mock Remove-Item { }
        Mock Get-PSReadLineOption { [pscustomobject]@{ HistorySavePath = "$TestDrive\ps_history.txt" } }
        Mock Get-WinEvent { @() }   # empty: the .NET ClearLog call in the loop body never runs
    }

    It 'in dry-run, logs WOULD and changes nothing' {
        $DryRun = $true

        Invoke-Cleanup

        Should -Invoke Write-Log -ParameterFilter { $Message -match '^WOULD: clear PS history' } -Times 1
        Should -Invoke Remove-Item -Times 0
        Should -Invoke Get-WinEvent -Times 0
        Should -Invoke cmd -Times 0
    }

    It 'clears the PowerShell history file' {
        Invoke-Cleanup

        Should -Invoke Get-PSReadLineOption -Times 1
        Should -Invoke Remove-Item -ParameterFilter { "$Path" -match 'ps_history\.txt$' } -Times 1
    }

    It 'enumerates every Windows event log to clear it' {
        Invoke-Cleanup

        Should -Invoke Get-WinEvent -ParameterFilter { $ListLog -contains '*' } -Times 1
    }

    It 'refuses scheduling even for existing external directories pending exact-file cleanup' {
        Invoke-Cleanup

        Should -Invoke cmd -Times 0
        Should -Invoke Write-Log -ParameterFilter { $Message -match 'not self-deleting' -and $Message -match 'by hand' } -Times 1
        [IO.File]::ReadAllText((Join-Path $OutDir 'retained.txt')) | Should -Be 'retain'
    }

    It 'history and log failures never escape or grant deletion permission' {
        Mock Remove-Item { throw 'access denied' }
        Mock Get-WinEvent { throw 'access denied' }

        { Invoke-Cleanup } | Should -Not -Throw

        Should -Invoke cmd -Times 0
        $State.Failures | Should -Contain 'clear PS history'
        $State.Failures | Should -Contain 'clear event logs'
        Should -Invoke Write-Log -ParameterFilter { $Message -match 'not self-deleting' -and $Message -match 'by hand' } -Times 1
    }

    It 'refuses a missing OutDir without an ErrorRecord crash' {
        $OutDir = "$TestDrive\missing-out"
        { Invoke-Cleanup } | Should -Not -Throw
        Should -Invoke cmd -Times 0
        Should -Invoke Write-Log -ParameterFilter { $Message -match 'unresolved' -and $Message -match 'missing-out' -and $Message -match 'by hand' } -Times 1
    }

    It 'refuses a missing ToolsDir without an ErrorRecord crash' {
        $ToolsDir = "$TestDrive\missing-tools"
        { Invoke-Cleanup } | Should -Not -Throw
        Should -Invoke cmd -Times 0
        Should -Invoke Write-Log -ParameterFilter { $Message -match 'unresolved' -and $Message -match 'missing-tools' -and $Message -match 'by hand' } -Times 1
    }

    It 'refuses an explicitly unresolved existing candidate with its original path in the diagnostic' {
        Mock Resolve-Path -ParameterFilter { "$Path" -eq $OutDir } { throw 'deliberately unresolved candidate' }
        { Invoke-Cleanup } | Should -Not -Throw
        Should -Invoke cmd -Times 0
        Should -Invoke Write-Log -ParameterFilter { $Message -match 'unresolved' -and $Message.Contains($OutDir) -and $Message -match 'by hand' } -Times 1
    }

    It 'refuses a script directory resolution failure' {
        Mock Resolve-Path -ParameterFilter { "$Path" -eq (Split-Path $PSScriptRoot -Parent) } { throw 'script directory unresolved' }
        { Invoke-Cleanup } | Should -Not -Throw
        Should -Invoke cmd -Times 0
        Should -Invoke Write-Log -ParameterFilter { $Message -match 'unresolved' -and $Message -match 'by hand' } -Times 1
    }

    It 'refuses an output directory contained in the source directory' {
        $OutDir = $PSScriptRoot
        { Invoke-Cleanup } | Should -Not -Throw
        Should -Invoke cmd -Times 0
        Should -Invoke Write-Log -ParameterFilter { $Message -match 'contains' -and $Message -match 'by hand' } -Times 1
    }

    It 'refuses a tools directory equal to the source directory' {
        $ToolsDir = Split-Path $PSScriptRoot -Parent
        { Invoke-Cleanup } | Should -Not -Throw
        Should -Invoke cmd -Times 0
        Should -Invoke Write-Log -ParameterFilter { $Message -match 'contains' -and $Message -match 'by hand' } -Times 1
    }
}

Describe 'Lock-Paths idempotency' {
    BeforeEach {
        Reset-TestState
        $OutDir = "$TestDrive\out"
        [System.IO.Directory]::CreateDirectory($OutDir) | Out-Null
        $lockTarget = "$TestDrive\lockme.txt"
        [System.IO.File]::WriteAllText($lockTarget, 'protect me')
        $LockPaths = @($lockTarget)

        Mock icacls { }
        Mock attrib { }
        Mock Write-Log { }

        $saveFile = Get-AclSaveFile $lockTarget
        [System.IO.File]::WriteAllText($saveFile, 'ORIGINAL')
    }

    It 'never overwrites an existing ACL save file and never calls icacls /save again' {
        Lock-Paths

        [System.IO.File]::ReadAllText($saveFile) | Should -Be 'ORIGINAL'
        Should -Invoke icacls -ParameterFilter { $args -contains '/save' } -Times 0
    }
}

Describe 'Invoke-Step exit code handling' {
    BeforeEach {
        Reset-TestState
        $DryRun = $false
        Mock Write-Log { }
    }

    It 'logs FAILED when the native command exits non-zero' {
        $result = Invoke-Step 'test' { & $trustedCmd /d /c exit 3 }

        $result | Should -BeFalse
        Should -Invoke Write-Log -ParameterFilter { $Message -match '^FAILED: test' } -Times 1
    }

    It 'does not log FAILED when the native command exits zero' {
        $result = Invoke-Step 'test' { & $trustedCmd /d /c exit 0 }

        $result | Should -BeTrue
        Should -Invoke Write-Log -ParameterFilter { $Message -match '^FAILED' } -Times 0
    }

    It 'with -RobocopyCodes, treats exit code 1 as success' {
        $result = Invoke-Step 'rc' { & $trustedCmd /d /c exit 1 } -RobocopyCodes

        $result | Should -BeTrue
        Should -Invoke Write-Log -ParameterFilter { $Message -match '^FAILED' } -Times 0
    }

    It 'with -RobocopyCodes, treats exit code 8 as failure' {
        $result = Invoke-Step 'rc' { & $trustedCmd /d /c exit 8 } -RobocopyCodes

        $result | Should -BeFalse
        Should -Invoke Write-Log -ParameterFilter { $Message -match '^FAILED: rc' } -Times 1
    }

    It 'logs FAILED and does not throw when the action throws' {
        { Invoke-Step 'boom' { throw 'kaboom' } } | Should -Not -Throw

        Should -Invoke Write-Log -ParameterFilter { $Message -match '^FAILED: boom' } -Times 1
    }

    It 'does not run the action in dry-run' {
        $DryRun = $true
        function Test-Marker { }
        Mock Test-Marker { }

        $result = Invoke-Step 'dry' { Test-Marker }

        Should -Invoke Test-Marker -Times 0
        $result | Should -BeFalse
        Should -Invoke Write-Log -ParameterFilter { $Message -eq 'WOULD: dry' } -Times 1
    }
}

}
