Describe 'Combined production boundaries' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'FixtureSafety.ps1')
        Assert-DefinitionSource (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        . (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        function Get-Service { [CmdletBinding()] param($Name) throw 'Denied service read' }
        function Stop-Service { [CmdletBinding()] param($Name,$InputObject,[switch]$Force) throw 'Denied service write' }
        function Set-Service { [CmdletBinding()] param($Name,$InputObject,$StartupType) throw 'Denied service write' }
        function Get-NetFirewallProfile { [CmdletBinding()] param($PolicyStore) throw 'Denied firewall read' }
        function Get-NetFirewallRule { [CmdletBinding()] param($Name,$PolicyStore,$Direction,$Action,$Enabled) throw 'Denied firewall read' }
        function Set-NetFirewallProfile { [CmdletBinding()] param($Profile,$Enabled,$DefaultInboundAction) throw 'Denied firewall write' }
        function New-NetFirewallRule { [CmdletBinding()] param($Name,$DisplayName,$Direction,$Protocol,$LocalPort,$RemotePort,$Action,$Service,$Program,$Profile,$PolicyStore) throw 'Denied firewall write' }
        function Remove-NetFirewallRule { [CmdletBinding()] param($Name,$InputObject) throw 'Denied firewall write' }
        function New-ItemProperty { [CmdletBinding()] param($Path,$Name,$Value,$PropertyType,[switch]$Force) throw 'Denied registry write' }
        function Get-ScheduledTask { [CmdletBinding()] param() throw 'Denied task read' }
        function Get-CimInstance { [CmdletBinding()] param($ClassName,$Namespace) throw 'Denied CIM read' }
        function Read-Host { [CmdletBinding()] param($Prompt,[switch]$AsSecureString) throw 'Denied prompt' }
    }
    BeforeEach {
        $DryRun=$false;$Unlock=$false;$Cleanup=$false;$OutDir=Join-Path $TestDrive 'out';$ToolsDir=Join-Path $TestDrive 'tools'
        $BackupPaths=@();$LockPaths=@();$DisableServices=@();$ToolsZip='';$AvInstallerUrl='';$InstallSysmon=$false;$LgpoExe='';$DodGpoDir=''
        $KeepOpenTcp=@(22);$AllowTcp=@(80);$AllowUdp=@();$BlockTcp=@();$BlockUdp=@();$AuthorizedUsers=@();$ExcludeUsers=@()
        $null=New-RunState;$State.IsDC=$false;$State.RdpPort=3389
        Mock Write-Log {};Mock Invoke-NativeLeaf {throw 'Denied native'};Mock Start-InstallerLeaf {throw 'Denied installer'}
        Mock Open-RecoveryWrite {throw 'Denied journal'};Mock Set-RecoveryProtection {throw 'Denied ACL'}
        Mock Get-RecoveryObject {throw 'Denied object'};Mock Get-CurrentWindowsIdentity {throw 'Denied identity'}
        Mock Get-AccountTokenSid {throw 'Denied token'};Mock Clear-EventLog {throw 'Denied logs'};Mock Clear-History {throw 'Denied history'}
        Mock Set-CFileDescriptor {throw 'Denied ACL'};Mock Set-CFileAttributes {throw 'Denied attributes'}
        Mock Start-DeferredScriptRemoval {throw 'Denied cleanup'}
    }
    It 'eligible recovery cancellation reports Partial and preserves earlier errors' {
        $State.Preconditions.RecoveryEligible=$true
        $State.Preconditions.RecoveryPlan.RuleOperations=@(@{Label='Keep';Proto='TCP';Port=22},@{Label='Allow';Proto='TCP';Port=80})
        Mock Add-Rule -ParameterFilter {$Port -eq 22} {throw 'ordinary'}
        Mock Add-Rule -ParameterFilter {$Port -eq 80} {throw [OperationCanceledException]::new()}
        {Invoke-FiniteRecovery} | Should -Throw
        $State.Cancelled | Should -BeTrue;$State.RecoveryStatus | Should -Be 'Partial'
        $State.Failures.Stage | Should -Contain 'RecoveryRule'
    }
    It 'native cancellation survives an ordinary GLOBAL restoration error' {
        Mock Assert-NativeApproval {};Mock Invoke-NativeLeaf {throw [OperationCanceledException]::new()}
        $prior=Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue;$value=if($prior){$prior.Value}else{$null}
        try {
            $global:LASTEXITCODE=77
            Mock Set-Variable -ParameterFilter {$Name -eq 'LASTEXITCODE' -and $Scope -eq 'Global' -and $Value -eq 77} {throw 'restore fault'}
            $caught=$null;try{Invoke-NativeCommand 'C:\fake\tool.exe' @('safe')}catch{$caught=$_}
            Test-RunCancellation $caught | Should -BeTrue;$State.Cancelled | Should -BeTrue
            $State.Failures.Operation | Should -Contain 'RestoreGlobalExit'
        } finally {if($prior){$global:LASTEXITCODE=$value}else{Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue}}
    }
    It 'journal cancellation survives close failure and never publishes' {
        $path=Join-Path $TestDrive 'pending';Mock Open-RecoveryWrite {Open-FixtureStream $Path ([IO.FileMode]::CreateNew)}
        Mock Set-RecoveryBytes {throw [OperationCanceledException]::new()}
        Mock Close-RecoveryWrite {Close-FixtureStream $Stream;throw 'close fault'}
        Mock Publish-RecoveryFile {throw 'must not publish'}
        $caught=$null;try{Write-RecoveryBytes $path ([byte[]]@(1))}catch{$caught=$_}
        Test-RunCancellation $caught | Should -BeTrue;$State.Cancelled | Should -BeTrue
        $State.Failures.Operation | Should -Contain 'CloseRecord';Should -Invoke Publish-RecoveryFile -Times 0
    }
    It 'ordinary journal error is retained when close cancels' {
        $path=Join-Path $TestDrive 'pending-close-cancels';Mock Open-RecoveryWrite {Open-FixtureStream $Path ([IO.FileMode]::CreateNew)}
        Mock Set-RecoveryBytes {throw 'write fault'}
        Mock Close-RecoveryWrite {Close-FixtureStream $Stream;throw [OperationCanceledException]::new()}
        $caught=$null;try{Write-RecoveryBytes $path ([byte[]]@(1))}catch{$caught=$_}
        Test-RunCancellation $caught | Should -BeTrue;$State.Failures.Operation | Should -Contain 'WriteRecord'
    }
    It 'failed keep controls forbid purge and profile changes' {
        Mock Get-ListeningPorts {New-ReadResult 'Complete'};Mock Get-FirewallSnapshot {New-ReadResult 'Complete' @([pscustomobject]@{Profiles=@();Rules=@()})}
        Mock Test-FirewallBackupReady {$true};Mock Add-DhcpControl {$true};Mock Add-Rule {$false}
        Mock Remove-InboundRules {};Mock Enable-Firewall {}
        try{Set-FirewallLockdown}catch{}
        Should -Invoke Add-Rule -Times 2
        Should -Invoke Remove-InboundRules -Times 0;Should -Invoke Enable-Firewall -Times 0
        $State.Preconditions.RecoveryPlan.ProfileOperations.Count | Should -Be 0
    }
    It 'service names are literal and never expand dependents with Force' {
        $DisableServices=@('svc*')
        Mock Get-Service {[pscustomobject]@{Name='svc1';DependentServices=@()}}
        Mock Stop-Service {};Mock Set-Service {}
        Disable-ExtraServices
        Should -Invoke Stop-Service -Times 0;Should -Invoke Set-Service -Times 0
        $State.Failures.Count | Should -BeGreaterThan 0
    }
    It 'service stop failure is separate from successful disable' {
        $DisableServices=@('svc1')
        Mock Get-Service {[pscustomobject]@{Name='svc1';DependentServices=@();Status='Running'}}
        Mock Stop-Service {throw 'stop failed'};Mock Set-Service {}
        Disable-ExtraServices
        Should -Invoke Set-Service -Times 1;$State.ServicesDisabled | Should -Contain 'svc1'
        $State.Failures.Count | Should -BeGreaterThan 0
    }
    It 'a literal service containing a dollar sign remains eligible without Force' {
        $DisableServices=@('MSSQL$FIXTURE')
        Mock Get-Service {[pscustomobject]@{Name='MSSQL$FIXTURE';DependentServices=@();Status='Running'}}
        Mock Stop-Service {};Mock Set-Service {}
        Disable-ExtraServices
        Should -Invoke Stop-Service -Times 1 -ParameterFilter {$InputObject.Name -eq 'MSSQL$FIXTURE' -and -not $Force}
        $State.ServicesDisabled | Should -Contain 'MSSQL$FIXTURE'
    }
    It 'failed requested tools archive cannot write PATH or EULA or run stale Sysmon' {
        $ToolsZip='C:\missing.zip';$InstallSysmon=$true
        Mock Initialize-ProtectedDirectory {};Mock Initialize-OwnedToolDirectory {};Mock Lock-AdminOnlyAcl {};Mock Expand-ToolsZip {$false}
        Mock Get-TlsProtocol {[Net.SecurityProtocolType]::Tls12};Mock Set-TlsProtocol {}
        Mock New-Item {};Mock Test-Path {$true};Mock Get-Item {throw 'stale registry path reached'}
        Mock New-ItemProperty {};Mock Invoke-NativeCommand {throw 'stale native reached'}
        try{Install-Tools}catch{}
        Should -Invoke New-ItemProperty -Times 0;Should -Invoke Invoke-NativeCommand -Times 0
        $State.ToolsInstalled | Should -BeFalse
    }
    It 'ordinary native error is retained when GLOBAL restoration cancels' {
        Mock Assert-NativeApproval {};Mock Invoke-NativeLeaf {throw 'fixed native failure'}
        $prior=Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue;$value=if($prior){$prior.Value}else{$null}
        try {
            $global:LASTEXITCODE=77
            Mock Set-Variable -ParameterFilter {$Name -eq 'LASTEXITCODE' -and $Scope -eq 'Global' -and $Value -eq 77} {throw [OperationCanceledException]::new()}
            $caught=$null;try{Invoke-NativeCommand 'C:\fake\tool.exe' @('safe')}catch{$caught=$_}
            Test-RunCancellation $caught | Should -BeTrue;$State.Cancelled | Should -BeTrue
            $State.Failures.Operation | Should -Contain Invocation;$State.Failures.Operation | Should -Contain RestoreGlobalExit
        }finally{if($prior){$global:LASTEXITCODE=$value}else{Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue}}
    }
}
