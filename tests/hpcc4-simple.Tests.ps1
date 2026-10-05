Describe 'Main script policy and recovery regressions (mocked host)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'FixtureSafety.ps1')
        Assert-DefinitionSource (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        . (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        function Get-LocalUser {[CmdletBinding()]param($SID,$Name)throw 'Denied users'}
        function Remove-LocalUser {[CmdletBinding()]param($SID,$Name)throw 'Denied delete'}
        function Set-LocalUser {[CmdletBinding()]param($SID,$Name,$Password)throw 'Denied password'}
        function Get-CimInstance {[CmdletBinding()]param($ClassName,$Namespace)throw 'Denied CIM'}
        function Get-ScheduledTask {[CmdletBinding()]param()throw 'Denied tasks'}
        function Get-LocalGroupMember {[CmdletBinding()]param($Group)throw 'Denied task-group read'}
        function Read-Host {[CmdletBinding()]param($Prompt,[switch]$AsSecureString)throw 'Denied prompt'}
        function Get-NetFirewallProfile {[CmdletBinding()]param($PolicyStore)throw 'Denied firewall'}
        function Get-NetFirewallRule {[CmdletBinding()]param($Name,$PolicyStore)throw 'Denied firewall'}
        function Set-NetFirewallProfile {[CmdletBinding()]param($Profile,$Enabled,$DefaultInboundAction)throw 'Denied firewall write'}
        function New-NetFirewallRule {[CmdletBinding()]param($Name,$DisplayName,$Direction,$Protocol,$LocalPort,$RemotePort,$Action,$Service,$Profile,$PolicyStore)throw 'Denied firewall write'}
        function Remove-NetFirewallRule {[CmdletBinding()]param($InputObject)throw 'Denied firewall write'}
        function Get-WindowsOptionalFeature {[CmdletBinding()]param([switch]$Online,$FeatureName)throw 'Denied feature read'}
        function Get-PSReadLineOption {[CmdletBinding()]param()throw 'Denied history read'}
        function Set-PSReadLineOption {[CmdletBinding()]param($HistorySaveStyle)throw 'Denied history write'}
        function New-TestUser {param($Name,$Rid,[bool]$Enabled=$true);[pscustomobject]@{Name=$Name;SID="S-1-5-21-1-2-3-$Rid";Enabled=$Enabled}}
        function New-TestRule {param($Name='HPCC4-Keep-TCP-3389',$Action='Allow',$Proto='TCP',$Port='3389')
            [pscustomobject]@{Name=$Name;Direction='Inbound';Action=$Action;Enabled='True';Profile='Any';Source='Local';Rule=[pscustomobject]@{Name=$Name};Port=@{Protocol=$Proto;LocalPort=$Port;RemotePort='Any'};Address=@{LocalAddress='Any';RemoteAddress='Any'};Application=@{Program='Any';Package='Any'};Service=@{Service='Any'};Interface=@{InterfaceAlias='Any'};Security=@{Authentication='NotRequired';Encryption='NotRequired'}}
        }
    }
    BeforeEach {
        $DryRun=$false;$Unlock=$false;$Cleanup=$false;$OutDir=Join-Path $TestDrive 'out';$ToolsDir=Join-Path $TestDrive 'tools'
        $KeepOpenTcp=@(22);$AllowTcp=@(80);$AllowUdp=@();$BlockTcp=@();$BlockUdp=@();$ExcludeUsers=@();$AuthorizedUsers=@();$LockPaths=@();$BackupPaths=@();$DisableServices=@()
        $ToolsZip='';$ToolsZipSha256='';$AvInstallerUrl='';$InstallSysmon=$false;$LgpoExe='';$DodGpoDir='';$DodGpoSelection=@()
        $null=New-RunState;$State.IsDC=$false;$State.RdpPort=3389;$script:RecoveryContext=$null;$script:DeploymentIdentity=$null
        Mock Read-Host {throw 'Denied prompt'};Mock Write-Log {};Mock Invoke-NativeLeaf {throw 'Denied native'};Mock Start-InstallerLeaf {throw 'Denied installer'}
        Mock Start-DeferredRemovalLeaf {throw 'Denied deferred child'};Mock Set-RecoveryProtection {throw 'Denied ACL'}
        Mock Get-CurrentWindowsIdentity {throw 'Denied identity'};Mock Get-RecoveryObject {throw 'Denied object'}
        Mock Open-RecoveryWrite {throw 'Denied file write'};Mock Open-ProtectedRecoveryFile {throw 'Denied file create'}
        Mock Copy-ProtectedInput {throw 'Denied copy'};Mock Expand-ProtectedArchive {throw 'Denied extraction'}
        Mock Set-RawRegistryValue {throw 'Denied registry'};Mock Get-RawRegistryValue {throw 'Denied registry read'}
        Mock Set-CFileDescriptor {throw 'Denied ACL'};Mock Set-CFileAttributes {throw 'Denied attributes'}
        Mock Clear-CPSReadLineMemory {throw 'Denied memory clear'};Mock Remove-CHistoryFile {throw 'Denied disk history'}
        Mock Clear-EventLog {throw 'Denied event clear'};Mock Clear-History {throw 'Denied session history'}
        Mock Get-StartupLinkTarget {throw 'Denied COM'}
    }
    Context 'Frozen account identity and dependency discovery' {
        BeforeEach {
            $script:users=@((New-TestUser operator 1000),(New-TestUser bob 1001),(New-TestUser service 1002),(New-TestUser guest 501 $false))
            $script:principals=@();Mock Get-LocalUser {$script:users};Mock Get-AccountTokenSid {'S-1-5-21-1-2-3-1000'}
            Mock Get-CimInstance {$script:principals | ForEach-Object {[pscustomobject]@{StartName=$_}}};Mock Get-ScheduledTask {@()}
            Mock Get-AccountIisPrincipals {New-ReadResult 'Absent'}
            Mock Remove-LocalUser {};Mock Set-LocalUser {}
        }
        It 'protects the actual token SID and conservative domain-name collisions' {
            $script:principals=@('CORP\service');$read=Get-AccountSnapshot
            $read.Status | Should -Be 'Complete';@($read.Items | Where-Object Protected).Name | Should -Contain 'operator'
            @($read.Items | Where-Object Protected).Name | Should -Contain 'service'
        }
        It 'protects task principals supplied as actual SIDs' {
            Mock Get-ScheduledTask {[pscustomobject]@{Principal=@{UserId='S-1-5-21-1-2-3-1001';GroupId=''}}}
            @((Get-AccountSnapshot).Items | Where-Object Name -eq bob).Protected | Should -BeTrue
        }
        It 'protects every user member of a group task principal' {
            Mock Get-ScheduledTask {[pscustomobject]@{Principal=@{UserId='';GroupId='fixture-group'}}}
            Mock Get-LocalGroupMember {[pscustomobject]@{ObjectClass='User';SID='S-1-5-21-1-2-3-1001';Name='HOST\bob'}}
            @((Get-AccountSnapshot).Items | Where-Object Name -eq bob).Protected | Should -BeTrue
        }
        It 'unresolved nested task groups fail closed before account prompts' {
            Mock Get-ScheduledTask {[pscustomobject]@{Principal=@{UserId='';GroupId='fixture-group'}}}
            Mock Get-LocalGroupMember {[pscustomobject]@{ObjectClass='Group';SID='S-1-5-32-544';Name='nested'}}
            Set-LocalPasswords;Should -Invoke Read-Host -Times 0;Should -Invoke Set-LocalUser -Times 0
            $State.Failures.Count | Should -BeGreaterThan 0
        }
        It 'failed dependency discovery cannot become a safe empty inventory' {
            Mock Get-CimInstance {throw 'source unavailable'};$AuthorizedUsers=@('operator')
            Remove-UnauthorizedUsers;Set-LocalPasswords
            Should -Invoke Remove-LocalUser -Times 0;Should -Invoke Set-LocalUser -Times 0;Should -Invoke Read-Host -Times 0
            $State.Failures.Count | Should -Be 2
        }
        It 'empty password targets never prompt for a password' {
            $ExcludeUsers=@('bob','service');Set-LocalPasswords;Should -Invoke Read-Host -Times 0
        }
        It 'does not mutate accounts on a domain controller' {
            $State.IsDC=$true;$AuthorizedUsers=@('operator');Remove-UnauthorizedUsers;Set-LocalPasswords
            Should -Invoke Read-Host -Times 0;Should -Invoke Set-LocalUser -Times 0;Should -Invoke Remove-LocalUser -Times 0
        }
        It 'late dependencies after consent prevent deletion' {
            $AuthorizedUsers=@('operator','service');Mock Read-Host {$script:principals=@('HOST\bob');'y'}
            Remove-UnauthorizedUsers;Should -Invoke Remove-LocalUser -Times 0
        }
        It 'rename/replacement/new accounts cannot broaden frozen approval' {
            $AuthorizedUsers=@('operator','service')
            Mock Read-Host {$script:users=@((New-TestUser operator 1000),(New-TestUser replacement 1001),(New-TestUser newcomer 1003),(New-TestUser service 1002));'y'}
            Remove-UnauthorizedUsers;Should -Invoke Remove-LocalUser -Times 0
        }
        It 'uses frozen SID for deletion and never deletes built-ins/token/exclusions' {
            $AuthorizedUsers=@('operator');$ExcludeUsers=@('service');Mock Read-Host {'y'}
            Remove-UnauthorizedUsers;Should -Invoke Remove-LocalUser -Times 1 -ParameterFilter {$SID -eq 'S-1-5-21-1-2-3-1001' -and -not $Name}
            $State.Deleted | Should -Contain bob
        }
        It 'empty authorization and declined consent do not delete anything' {
            Remove-UnauthorizedUsers;Should -Invoke Read-Host -Times 0
            $AuthorizedUsers=@('operator');Mock Read-Host {'n'};Remove-UnauthorizedUsers;Should -Invoke Remove-LocalUser -Times 0
        }
        It 'disposes the shared secret and refreshes immediately before every SID write' {
            $ExcludeUsers=@('service');$script:secret1=ConvertTo-SecureString 'fixture-only' -AsPlainText -Force;$script:secret2=ConvertTo-SecureString 'fixture-only' -AsPlainText -Force;$script:prompt=0
            Mock Read-Host {$script:prompt++;switch($script:prompt){1{'y'} 2{$script:secret1} 3{$script:secret2}}}
            Set-LocalPasswords;Should -Invoke Set-LocalUser -Times 1 -ParameterFilter {$SID -eq 'S-1-5-21-1-2-3-1001' -and [object]::ReferenceEquals($Password,$script:secret1)}
            {$script:secret1.Copy()} | Should -Throw;{$script:secret2.Copy()} | Should -Throw
        }
        It 'a dependency appearing during secret input prevents password mutation and disposes input' {
            $ExcludeUsers=@('service');$script:secret1=ConvertTo-SecureString 'fixture-only' -AsPlainText -Force;$script:prompt=0
            Mock Read-Host {$script:prompt++;if($script:prompt -eq 1){'y'}else{$script:principals=@('CORP\bob');$script:secret1}}
            Set-LocalPasswords;Should -Invoke Set-LocalUser -Times 0;{$script:secret1.Copy()} | Should -Throw
        }
    }
    Context 'Firewall control/policy gates' {
        BeforeEach {
            $script:profiles=@('Domain','Private','Public' | ForEach-Object {@{Name=$_;Enabled='True';DefaultInboundAction='Block';AllowLocalFirewallRules='NotConfigured'}})
            $script:rules=@();Mock Get-FirewallSnapshot {New-ReadResult 'Complete' @([pscustomobject]@{Profiles=$profiles;Rules=$rules})}
            Mock Get-ListeningPorts {New-ReadResult 'Complete'};Mock Test-FirewallBackupReady {$true}
            Mock Add-Rule {$true};Mock Add-DhcpControl {$true};Mock Assert-EffectiveControl {};Mock Remove-InboundRules {};Mock Enable-Firewall {}
        }
        It 'controls precede purge/default block and grant finite profile authority' {
            $script:order=@();Mock Add-Rule {$script:order+='control';$true};Mock Remove-InboundRules {$script:order+='purge'};Mock Enable-Firewall {$script:order+='profile'}
            Set-FirewallLockdown;$order[-2] | Should -Be purge;$order[-1] | Should -Be profile
            $State.Preconditions.RecoveryPlan.ProfileOperations.Count | Should -Be 3
        }
        It 'DC retains defaults and all rules' {$State.IsDC=$true;Set-FirewallLockdown;Should -Invoke Remove-InboundRules -Times 0;Should -Invoke Enable-Firewall -Times 1 -ParameterFilter {-not $BlockInbound}}
        It 'missing backup forbids purge but independently permits checked default block' {Mock Test-FirewallBackupReady {$false};Set-FirewallLockdown;Should -Invoke Remove-InboundRules -Times 0;Should -Invoke Enable-Firewall -Times 1 -ParameterFilter {$BlockInbound}}
        It 'declined startup leaves no profile authority' {Mock Get-ListeningPorts {New-ReadResult 'Complete' @([pscustomobject]@{Proto='TCP';Port=1234})};Mock Read-Host {'n'};Set-FirewallLockdown;Should -Invoke Enable-Firewall -Times 0;$State.Preconditions.RecoveryPlan.StartupDecisionEstablished | Should -BeFalse}
        It 'incomplete source observations refuse before controls or profile writes' {Mock Get-FirewallSnapshot {New-ReadResult 'Failed'};{Set-FirewallLockdown} | Should -Throw;Should -Invoke Add-Rule -Times 0;Should -Invoke Enable-Firewall -Times 0}
        It 'a misleading rule name is insufficient proof of a valid control' {$rule=New-TestRule;$rule.Enabled='False';Test-ControlRule $rule 'TCP' 3389 | Should -BeFalse;$rule.Enabled='True';$rule.Port.LocalPort=22;Test-ControlRule $rule 'TCP' 3389 | Should -BeFalse}
        It 'range and Any blocks are recognized as control conflicts' {Test-FirewallPortMatch @('3000-4000') 3389 | Should -BeTrue;Test-FirewallPortMatch @('Any') 22 | Should -BeTrue;Test-FirewallPortMatch @('80') 22 | Should -BeFalse}
        It 'DHCP prefix names do not grant preservation of arbitrary ports/services' {$rule=New-TestRule 'HPCC4-DHCP-fake' 'Allow' 'UDP' '68';$rule.Port.RemotePort='67';Test-ControlRule $rule 'UDP' 68 'Allow' 67 'Dhcp' | Should -BeFalse;$rule.Service.Service='Dhcp';Test-ControlRule $rule 'UDP' 68 'Allow' 67 'Dhcp' | Should -BeTrue}
    }
    Context 'Exact ACL original and partial retry' {
        BeforeEach {
            $path=Join-Path $TestDrive 'target';$id=@{Policy='VolumeFileId';Value='fixture:1'}
            $prior=@{Identity=$id;Sddl='original-descriptor';Attributes=0};$intended=@{Identity=$id;Sddl='locked-descriptor';Attributes=1}
            $script:record=@{SchemaVersion=1;RecordId=[guid]::NewGuid().ToString('D');Revision=2;RunId=$State.RunId;MachineId=[guid]::NewGuid().ToString('D');Kind='Acl';ResourceId=$path.ToUpperInvariant();ResourceIdentity=$id;CanonicalPath=$path;Ownership='Preexisting';State='Applied';Prior=$prior;IntendedState=$intended;AppliedObservation=$intended;Artifact=@{CanonicalPath='';Digest='';Complete=$false};ChangedByRun=$true;Limits=@()}
            $script:observed=Copy-CRecoveryRecord $intended
            Mock Assert-RecoveryRecord {};Mock Get-CanonicalFilePath {$Path};Mock Read-RecoveryRecords {New-ReadResult 'Complete' @($record)}
            Mock Get-CFileObservation {$observed};Mock Write-RecoveryRecord {$script:record=Copy-CRecoveryRecord $Record}
            Mock Set-CFileDescriptor {$script:observed.Sddl=$Sddl};Mock Set-CFileAttributes {$script:observed.Attributes=$Attributes}
        }
        It 'restores exact original attributes and descriptor before retiring the record' {Restore-AclRecoveryRecord $record | Should -BeTrue;Test-DataEqual $observed $record.Prior | Should -BeTrue;$record.State | Should -Be Restored}
        It 'later unrelated descriptor/attribute changes are retained as conflicts' {$observed.Sddl='later-unrelated';Restore-AclRecoveryRecord $record | Should -BeFalse;Should -Invoke Set-CFileDescriptor -Times 0;Should -Invoke Set-CFileAttributes -Times 0;$record.State | Should -Be Applied}
        It 'replacement identity is never restored' {$observed.Identity=@{Policy='VolumeFileId';Value='replacement'};Restore-AclRecoveryRecord $record | Should -BeFalse;Should -Invoke Set-CFileDescriptor -Times 0}
        It 'partial attribute failure records a verified intermediate and allows only that same-object retry' {
            Mock Set-CFileAttributes {throw 'attribute failure'};Restore-AclRecoveryRecord $record | Should -BeFalse;$record.State | Should -Be RestoreFailed
            Mock Set-CFileAttributes {$script:observed.Attributes=$Attributes};Restore-AclRecoveryRecord $record | Should -BeTrue
            Should -Invoke Set-CFileDescriptor -Times 1;$record.State | Should -Be Restored
        }
        It 'an Intent crash gap not matching the original is manual recovery' {$record.State='Intent';$record.AppliedObservation=$null;$record.Revision=1;$observed.Sddl='unknown-partial';Restore-AclRecoveryRecord $record | Should -BeFalse;Should -Invoke Set-CFileDescriptor -Times 0}
        It 'failed intermediate publication stops attribute restore and keeps the initiating evidence' {Mock Write-RecoveryRecord {throw 'publication failed'};Restore-AclRecoveryRecord $record | Should -BeFalse;Should -Invoke Set-CFileAttributes -Times 0;$record.State | Should -Be Applied}
    }
    Context 'Cleanup and report seams' {
        It 'dry-run calls no history, log or deferred-process mutation' {$DryRun=$true;Invoke-Cleanup;Should -Invoke Clear-History -Times 0;Should -Invoke Clear-EventLog -Times 0;Should -Invoke Start-DeferredRemovalLeaf -Times 0}
        It 'partial per-log failures preserve independent attempts and honest outcomes' {
            Mock Get-PSReadLineOption {@{HistorySavePath=''}};Mock Set-PSReadLineOption {};Mock Clear-CPSReadLineMemory {};Mock Clear-History {}
            Mock Get-CCleanupLogs {@('one','two')};Mock Clear-EventLog -ParameterFilter {$LogName -eq 'one'} {throw 'denied'};Mock Clear-EventLog -ParameterFilter {$LogName -eq 'two'} {}
            Invoke-Cleanup;Should -Invoke Clear-EventLog -Times 2;Should -Invoke Set-PSReadLineOption -Times 1 -ParameterFilter {$HistorySaveStyle -eq 'SaveNothing'};$State.Failures.Count | Should -BeGreaterThan 0
        }
        It 'replacement deployed files never schedule removal' {$script:DeploymentIdentity=@{Path='C:\fake\deployed.ps1';Identity=@{Policy='VolumeFileId';Value='old'};Digest=('a'*64)};Mock Assert-TrustedPath {};Mock Get-RecoveryObject {[pscustomobject]@{Identity=@{Policy='VolumeFileId';Value='new'}}};{Start-DeferredScriptRemoval 'C:\fake\deployed.ps1'} | Should -Throw;Should -Invoke Start-DeferredRemovalLeaf -Times 0}
        It 'persistence identity is disposed exactly once and failed sources remain distinct' {
            $counter=@{Calls=0};$script:fixtureIdentity=[pscustomobject]@{User=@{Value='S-1-5-21-1-2-3-1000'};Counter=$counter} | Add-Member ScriptMethod Dispose {$this.Counter.Calls++} -PassThru
            Mock Get-CurrentWindowsIdentity {$script:fixtureIdentity};Mock Read-PersistenceSource {New-ReadResult 'Failed'}
            $DryRun=$true;Get-PersistenceReport;$counter.Calls | Should -Be 1;$State.PersistenceSources.Count | Should -BeGreaterThan 5;$State.Failures.Operation | Should -Contain Coverage
        }
        It 'registry multi-string members remain separate full payload rows' {$rows=@(New-PersistenceRows 'registry' 'member' @('first','second'));$rows.Count | Should -Be 2;$rows[1].Command | Should -Be second}
    }
}
