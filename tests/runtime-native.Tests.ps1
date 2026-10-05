Describe 'B trust, TLS and harmless-native matrix' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'FixtureSafety.ps1')
        Assert-DefinitionSource (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        function New-Item { [CmdletBinding()] param($Path,$ItemType,[switch]$Force) throw 'Forbidden filesystem mutation' }
        function Set-Acl { [CmdletBinding()] param($LiteralPath,$AclObject) throw 'Forbidden ACL mutation' }
        function Remove-Item { [CmdletBinding()] param($Path,$LiteralPath,[switch]$Recurse,[switch]$Force) throw 'Forbidden filesystem mutation' }
        function Invoke-WebRequest { [CmdletBinding()] param($Uri,$OutFile,[switch]$UseBasicParsing) throw 'Forbidden download' }
        function Start-Process { [CmdletBinding()] param($FilePath) throw 'Forbidden process' }
        function New-ItemProperty { [CmdletBinding()] param($Path,$Name,$Value,$PropertyType,[switch]$Force) throw 'Forbidden registry' }
        function Stop-Service { [CmdletBinding()] param($Name,[switch]$Force) throw 'Forbidden service' }
        function Set-Service { [CmdletBinding()] param($Name,$StartupType) throw 'Forbidden service' }
        function Remove-LocalUser { [CmdletBinding()] param($SID,$Name) throw 'Forbidden account' }
        function Set-LocalUser { [CmdletBinding()] param($Name,$Password) throw 'Forbidden password' }
        function New-NetFirewallRule { [CmdletBinding()] param($Name,$DisplayName,$Direction,$Protocol,$LocalPort,$Action) throw 'Forbidden firewall' }
        function Remove-NetFirewallRule { [CmdletBinding()] param($Name,$DisplayName) throw 'Forbidden firewall' }
        . (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        function Set-NetFirewallProfile { [CmdletBinding()] param($Profile,$Enabled) throw 'Forbidden firewall' }
        function Write-Log { param($Message) }
        $script:installToolsBody=(Get-Command Install-Tools).ScriptBlock
        function New-FixtureRecord {
            @{ SchemaVersion=1; RecordId=[guid]::NewGuid().ToString('D'); Revision=1; RunId=$State.RunId; MachineId='11111111-1111-1111-1111-111111111111'; Kind='Storage'; ResourceId=$OutDir.ToUpperInvariant(); ResourceIdentity=@{Policy='VolumeFileId';Value='fixture:1'}; CanonicalPath=$OutDir; Ownership='Preexisting'; State='Intent'; Prior=@{Exists=$true;Value='original'}; IntendedState=@{Value='intended'}; AppliedObservation=$null; Artifact=@{CanonicalPath='';Digest='';Complete=$false}; ChangedByRun=$false; Limits=@('fixture') }
        }
    }
    BeforeEach {
        $DryRun=$false; $Unlock=$false; $Cleanup=$false
        $OutDir="$TestDrive\out"; $ToolsDir="$TestDrive\tools"
        $BackupPaths=@(); $LockPaths=@(); $KeepOpenTcp=@(22); $AllowTcp=@(80); $AllowUdp=@(53); $BlockTcp=@(); $BlockUdp=@()
        $ToolsZipSha256=''; $AvInstallerUrl=''; $ToolsZip=''
        $null=New-RunState; $script:RecoveryContext=$null
        Mock Get-LocalVolume { [pscustomobject]@{ Mapping='\Device\HarddiskVolume3'; Format='NTFS'; Type='Fixed'; Roots=@($Drive+'\') } }
        Mock Get-ChildItem {Get-FixtureEntries $(if($LiteralPath){$LiteralPath}else{$Path}) $(if($Filter){$Filter}else{'*'})}
        Mock Get-Content {Get-FixtureContent $(if($LiteralPath){$LiteralPath}else{$Path}) -Raw:$Raw}
        Mock Get-Item {Get-FixtureItem $(if($LiteralPath){$LiteralPath}else{$Path})}
        Mock Test-Path {Test-FixtureExists $(if($LiteralPath){$LiteralPath}else{$Path})}
        Mock Get-CurrentWindowsIdentity { throw 'Forbidden identity' }
        Mock Get-ListeningPorts {New-ReadResult 'Complete'}
        Mock Get-FirewallSnapshot {New-ReadResult 'Complete' @([pscustomobject]@{Profiles=@();Rules=@()})}
        Mock Get-AccountSnapshot {New-ReadResult 'Complete'}
        Mock Initialize-DeploymentIdentity {}
        Mock Get-RecoveryObject { throw 'Forbidden object/ACL' }
        Mock Get-RecoveryLockObject { throw 'Forbidden lock descriptor' }
        Mock Get-RecoveryMachineId { throw 'Forbidden registry' }
        Mock New-RecoveryDirectory { throw 'Forbidden directory' }
        Mock Set-RecoveryProtection { throw 'Forbidden ACL mutation' }
        Mock Open-RecoveryLock { throw 'Forbidden lock IO' }
        Mock Open-ProtectedRecoveryFile {throw 'Forbidden ACL-aware file creation'}
        Mock Initialize-ObjectIdentityApi {throw 'Forbidden native/CLR initialization'}
        Mock Open-RecoveryWrite { throw 'Forbidden record IO' }
        Mock Set-RecoveryBytes { throw 'Forbidden record write' }
        Mock Flush-RecoveryWrite { throw 'Forbidden record flush' }
        Mock Close-RecoveryWrite { throw 'Forbidden record close' }
        Mock Publish-RecoveryFile { throw 'Forbidden publication' }
        Mock Invoke-NativeLeaf { throw 'Forbidden native' }
        Mock Start-InstallerLeaf { throw 'Forbidden installer' }
        Mock Get-NativeFileDigest { throw 'Forbidden artifact read' }
        Mock Get-RuntimeRole { throw 'Forbidden CIM' }
        Mock Get-RuntimeRdpPort { throw 'Forbidden registry' }
        Mock Test-IsAdmin { throw 'Forbidden host admin' }
        Mock Get-TlsProtocol { throw 'Forbidden TLS' }
        Mock Set-TlsProtocol { throw 'Forbidden TLS mutation' }
        Mock Set-NetFirewallProfile { throw 'Forbidden firewall' }
        foreach ($stage in 'Backup-Targets','Set-FirewallLockdown','Remove-UnauthorizedUsers','Set-LocalPasswords','Disable-ExtraServices','Get-PersistenceReport','Install-DodGpo','Install-Tools','Lock-Paths','Unlock-Paths','Invoke-Cleanup','Write-Summary','Add-Rule') { Mock $stage { throw 'Forbidden domain stage' } }
    }
    AfterEach { Close-RecoverySession }

    Context 'approval machinery with protected file descriptor fixtures' {
        BeforeEach {
            $script:inboxFixture=Join-Path $TestDrive ([guid]::NewGuid().ToString());New-FixtureDirectory $inboxFixture
            foreach($name in 'icacls.exe','attrib.exe','robocopy.exe','netsh.exe','gpupdate.exe'){Write-FixtureText (Join-Path $inboxFixture $name) 'fixture bytes; never executed'}
            $script:external=Join-Path $inboxFixture 'LGPO.exe';Write-FixtureText $external 'fixture external bytes; never executed'
            Mock Assert-SupportedEngine {}
            Mock Get-OsSystemDirectory {$inboxFixture}
            Mock Assert-TrustedPath {}
            Mock Get-RecoveryObject {[pscustomobject]@{Identity=@{Policy='VolumeFileId';Value='fixture:1'}}}
            Mock Get-NativeFileDigest {('a'*64)}
        }
        It 'unknown native names and unapproved external files refuse before launch' {
            {Get-TrustedNativePath 'cmd.exe'} | Should -Throw
            {Invoke-NativeCommand $external @('/g','fixed')} | Should -Throw
            Should -Invoke Invoke-NativeLeaf -Times 0
        }
        It 'inbox resolver ignores mutable environment and simple shadow functions' {
            $oldWindir=$env:windir;$oldRoot=$env:SystemRoot;$oldPath=$env:PATH
            try {
                $env:windir='C:\spoof';$env:SystemRoot='C:\spoof';$env:PATH='C:\spoof'
                function icacls.exe {throw 'Shadow function must not run'}
                $path=Get-TrustedNativePath 'icacls.exe';$path | Should -Be (Join-Path $inboxFixture 'icacls.exe')
                $State.Preconditions.NativeApprovals[$path].TrustPolicy | Should -Be 'Inbox'
                Mock Invoke-NativeLeaf { $ExecutablePath | Should -Be (Join-Path $inboxFixture 'icacls.exe');$global:LASTEXITCODE=0 }
                (Invoke-NativeCommand $path @('fixed')).ExitCode | Should -Be 0
            } finally {$env:windir=$oldWindir;$env:SystemRoot=$oldRoot;$env:PATH=$oldPath}
        }
        It 'external role registers exact map and checks digest/identity again' {
            @(Register-NativeApproval $external 'LGPO' ('a'*64) 'PinnedDigest' @{Policy='VolumeFileId';Value='fixture:1'}).Count | Should -Be 0
            $approval=$State.Preconditions.NativeApprovals[$external];@($approval.Keys).Count | Should -Be 4;$approval.Role | Should -Be 'LGPO'
            Mock Get-NativeFileDigest {('b'*64)}
            {Assert-NativeApproval $external} | Should -Throw
            Should -Invoke Invoke-NativeLeaf -Times 0
        }
        It 'external identity/signature <Fault> refuses' -ForEach @(@{Fault='identity'},@{Fault='signature'},@{Fault='signer'}) {
            $AvInstallerExpectedSigner='Approved'
            Mock Get-AuthenticodeSignature {[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=Approved'}}}
            Register-NativeApproval $external 'AV' ('a'*64) 'ExpectedSigner' @{Policy='VolumeFileId';Value='fixture:1'}
            switch($Fault){identity{Mock Get-RecoveryObject {[pscustomobject]@{Identity=@{Policy='VolumeFileId';Value='replacement'}}}} signature{Mock Get-AuthenticodeSignature {[pscustomobject]@{Status='NotSigned';SignerCertificate=$null}}} signer{Mock Get-AuthenticodeSignature {[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=Other'}}}}}
            {Start-ApprovedInstaller $external} | Should -Throw;Should -Invoke Start-InstallerLeaf -Times 0
        }
        It 'AV launch acknowledges only an approved AV role' {
            Register-NativeApproval $external 'AV' ('a'*64) 'PinnedDigest' @{Policy='VolumeFileId';Value='fixture:1'}
            Mock Start-InstallerLeaf {'incidental'}
            $r=@(Start-ApprovedInstaller $external);$r.Count | Should -Be 1;$r[0] | Should -BeTrue
        }
        It 'appcmd consumers unwrap Output rows and retain failed dependency status' {
            New-FixtureDirectory (Join-Path $inboxFixture 'inetsrv');Write-FixtureText (Join-Path $inboxFixture 'inetsrv\appcmd.exe') 'fixture'
            function Get-WindowsOptionalFeature {[CmdletBinding()]param([switch]$Online,$FeatureName)throw 'Denied feature read'}
            Mock Get-WindowsOptionalFeature {[pscustomobject]@{State='Enabled'}}
            Mock Invoke-NativeLeaf {'HOST\pool';$global:LASTEXITCODE=0}
            $read=Get-AccountIisPrincipals;$read.Status | Should -Be Complete;$read.Items | Should -Be @('HOST\pool')
            Mock Invoke-NativeLeaf {throw 'appcmd failure'}
            (Get-AccountIisPrincipals).Status | Should -Be Failed
        }
    }
    Context 'TLS and caller preference restoration with all mutators faked' {
        BeforeEach {
            $script:tlsProtocol=[Net.SecurityProtocolType]::Tls11
            $AvInstallerUrl='https://example.invalid/fixed.exe';$ToolsZip='';$ToolsDir=Join-Path $TestDrive 'tls-tools';$OutDir=Join-Path $TestDrive 'tls-out'
            Mock Get-TlsProtocol {$tlsProtocol}
            Mock Set-TlsProtocol {$script:tlsProtocol=$Value}
            Mock New-Item {}
            Mock New-ItemProperty {}
            Mock Lock-AdminOnlyAcl {}
            Mock Initialize-ProtectedDirectory {};Mock Initialize-OwnedToolDirectory {}
            Mock Approve-RoleExecutable {$Path}
            Mock Set-OwnedRegistryValue {}
            Mock Assert-TrustedPath {}
            Mock Invoke-WebRequest {'incidental'}
            Mock Get-AuthenticodeSignature {[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=Fixture'}}}
            Mock Get-Item {[pscustomobject]@{} | Add-Member -MemberType ScriptMethod -Name GetValue -Value {'C:\Windows'} -PassThru}
        }
        It 'restores complete TLS value and caller progress after <Outcome>' -ForEach @(@{Outcome='success'},@{Outcome='download error'},@{Outcome='ACL early return'},@{Outcome='DryRun'}) {
            $before=$tlsProtocol;$ProgressPreference='Continue'
            switch($Outcome){'download error'{Mock Invoke-WebRequest {throw 'download fault'}} 'ACL early return'{Mock Lock-AdminOnlyAcl {throw 'ACL fault'}} DryRun{$DryRun=$true}}
            try{$null=& $installToolsBody}catch{if($Outcome -ne 'ACL early return'){throw}}
            $tlsProtocol | Should -Be $before;$ProgressPreference | Should -Be 'Continue'
            if($Outcome -in 'DryRun','ACL early return'){Should -Invoke Set-TlsProtocol -Times 0;Should -Invoke Invoke-WebRequest -Times 0}else{Should -Invoke Set-TlsProtocol -Times 2}
            if($Outcome -eq 'ACL early return'){Should -Invoke Invoke-WebRequest -Times 0}
        }
    }
}
