Describe 'B bootstrap and trust contracts (fixture only)' {
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
        function New-DescriptorObject {
            param([string]$Sddl='O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',[bool]$Directory=$true,[int]$Attributes=16,[bool]$Protected=$true)
            [pscustomobject]@{ Directory=$Directory;Attributes=$Attributes;Identity=@{Policy='VolumeFileId';Value='fixture:1'};Acl=[pscustomobject]@{Sddl=$Sddl;AreAccessRulesProtected=$Protected};Length=0 }
        }

        function Set-NetFirewallProfile { [CmdletBinding()] param($Profile,$Enabled) throw 'Forbidden firewall' }
        function Write-Log { param($Message) }
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

    Context 'security descriptor acceptance predicate' {
        It 'accepts approved OS owner <Owner> with ordinary read/traverse' -ForEach @(@{Owner='SY'},@{Owner='BA'},@{Owner='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'}) {
            $o=New-DescriptorObject "O:$Owner`G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)"
            {Assert-ObjectProtection $o -NoChildCreate} | Should -Not -Throw
        }
        It 'ancestor sibling creation alone is accepted, immediate parent creation is refused' {
            $o=New-DescriptorObject 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x6;;;BU)'
            {Assert-ObjectProtection $o} | Should -Not -Throw
            {Assert-ObjectProtection $o -NoChildCreate} | Should -Throw
        }
        It 'container-inheritable mutation <Right> is refused before new child creation' -ForEach @(@{Right='0x2'},@{Right='0x4'},@{Right='0x40'},@{Right='0x40000'},@{Right='0x80000'}) {
            $o=New-DescriptorObject "O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;CIIO;$Right;;;BU)"
            {Assert-ObjectProtection $o -NoChildCreate} | Should -Not -Throw
            {Assert-ObjectProtection $o -NoChildCreate -CheckChildInheritance} | Should -Throw
        }
        It 'protected creation descriptor names owner and only Administrators and SYSTEM' {
            foreach($file in $false,$true){
                $security=New-RecoverySecurity -File:$file
                $raw=[Security.AccessControl.RawSecurityDescriptor]::new($security.GetSecurityDescriptorSddlForm('All'))
                $raw.Owner.Value | Should -Be 'S-1-5-32-544'
                ($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) | Should -Not -Be 0
                $raw.DiscretionaryAcl.Count | Should -Be 2
                @($raw.DiscretionaryAcl | ForEach-Object {$_.SecurityIdentifier.Value}) | Should -Contain 'S-1-5-18'
                @($raw.DiscretionaryAcl | ForEach-Object {$_.SecurityIdentifier.Value}) | Should -Contain 'S-1-5-32-544'
            }
        }
        It 'duplicate volume roots <Roots> refuse both equivalent drive spellings' -ForEach @(@{Roots=@('C:\','Z:\')},@{Roots=@('C:\','C:\mount\')}) {
            Mock Get-LocalVolume {[pscustomobject]@{Mapping='\Device\HarddiskVolume3';Format='NTFS';Type='Fixed';Roots=$Roots}}
            {Get-CanonicalFilePath 'C:\same'} | Should -Throw
            {Get-CanonicalFilePath 'Z:\same'} | Should -Throw
        }
        It 'untrusted object authority <Right> is refused' -ForEach @(@{Right='0x40'},@{Right='0x10000'},@{Right='0x40000'},@{Right='0x80000'},@{Right='0x10'},@{Right='0x100'},@{Right='GA'},@{Right='GW'}) {
            $o=New-DescriptorObject "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;$Right;;;BU)"
            {Assert-ObjectProtection $o} | Should -Throw
        }
        It 'metadata read grant is refused before confidential publication' {$o=New-DescriptorObject 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FR;;;BU)';{Assert-ObjectProtection $o -Confidential} | Should -Throw}
        It 'invalid descriptor <Fault> refuses' -ForEach @(@{Fault='owner'},@{Fault='null DACL'},@{Fault='reparse'},@{Fault='unprotected'},@{Fault='missing SYSTEM'},@{Fault='missing identity'},@{Fault='object ACE'}) {
            $o=New-DescriptorObject
            switch($Fault){owner{$o.Acl.Sddl='O:BUG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'} 'null DACL'{$o.Acl.Sddl='O:BAG:BAD:NO_ACCESS_CONTROL'} reparse{$o.Attributes=1024} unprotected{$o.Acl.AreAccessRulesProtected=$false} 'missing SYSTEM'{$o.Acl.Sddl='O:BAG:BAD:P(A;;FA;;;BA)'} 'missing identity'{$o.Identity=$null} 'object ACE'{$o.Acl.Sddl='O:BAG:BAD:P(OA;;FA;11111111-1111-1111-1111-111111111111;;BA)'}}
            {Assert-ObjectProtection $o -Confidential} | Should -Throw
        }
        It 'file write permission refuses even where ancestor creation was allowed' {$o=New-DescriptorObject 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x2;;;BU)' $false 0;{Assert-ObjectProtection $o} | Should -Throw}
        It 'confidential Administrators and SYSTEM descriptor is usable' { {Assert-ObjectProtection (New-DescriptorObject) -NoChildCreate -Confidential} | Should -Not -Throw }
        It 'unsupported volume/alias <Form> refuses' -ForEach @(@{Form='SUBST';Mapping='\??\C:\real';Format='NTFS';Type='Fixed';Roots=@('C:\')},@{Form='UNC mapping';Mapping='\Device\LanmanRedirector\share';Format='NTFS';Type='Network'},@{Form='ReFS';Mapping='\Device\HarddiskVolume3';Format='ReFS';Type='Fixed';Roots=@('C:\')}) {
            Mock Get-LocalVolume { [pscustomobject]@{Mapping=$Mapping;Format=$Format;Type=$Type;Roots=$Roots} }
            {Get-CanonicalFilePath 'C:\fixture'} | Should -Throw
        }
        It 'unsupported path <Path> refuses' -ForEach @(@{Path='C:relative'},@{Path='\\host\share\a'},@{Path='HKLM:\key'},@{Path='C:\'},@{Path='C:\a~1\b'},@{Path='C:\a.\b'},@{Path='C:\CON.txt'},@{Path='C:\a:stream'}) { {Get-CanonicalFilePath $Path} | Should -Throw }
    }
    Context 'usable protected bootstrap with bounded real fixture IO' {
        BeforeEach {
            $script:systemFixture=Join-Path $TestDrive ([guid]::NewGuid().ToString());New-FixtureDirectory $systemFixture;New-FixtureDirectory (Join-Path $systemFixture 'config')
            $OutDir=Join-Path $TestDrive ([guid]::NewGuid().ToString())
            $script:protectedPaths=@{};$script:events=@();$script:objectEpoch=1
            Mock Get-OsSystemDirectory {$systemFixture}
            Mock Get-RecoveryMachineId {'11111111-1111-1111-1111-111111111111'}
            Mock Get-RecoveryObject {
                if($Path.StartsWith($TestDrive+'\',[StringComparison]::OrdinalIgnoreCase)) {
                    $safe=Assert-FixturePath $Path
                    $item=Get-Item -LiteralPath $safe -Force -ErrorAction Stop
                    $o=New-DescriptorObject 'O:BAG:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)' ([bool]$item.PSIsContainer) ([int]$item.Attributes) $false
                    if($protectedPaths.ContainsKey($safe) -or (-not $item.PSIsContainer -and $protectedPaths.ContainsKey([IO.Path]::GetDirectoryName($safe)))) {$o=New-DescriptorObject 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)' ([bool]$item.PSIsContainer) ([int]$item.Attributes) ([bool]$item.PSIsContainer)}
                    $o.Identity=@{Policy='VolumeFileId';Value=((Get-TextDigest $safe)+'|'+$objectEpoch)};$o.Length=if($item.PSIsContainer){0}else{$item.Length};$o
                } else {New-DescriptorObject 'O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)' }
            }
            Mock New-RecoveryDirectory {
                $safe=Assert-FixturePath $Path
                if($safe -eq $OutDir){$r=Read-RecoveryRecords $OutDir 'Storage';@($r.Items | Where-Object State -eq 'Intent').Count | Should -Be 1;$script:events+='OutDirCreateAfterIntent'}
                New-FixtureDirectory $safe
            }
            Mock Set-RecoveryProtection {$safe=Assert-FixturePath $Path;if(@(Get-ChildItem -LiteralPath $safe -Force).Count){throw 'Metadata published before protection'};$script:protectedPaths[$safe]=$true;$script:events+='Protect'}
            Mock Open-RecoveryLock {Open-FixtureStream $Path $(if($ExistingOnly){[IO.FileMode]::Open}else{[IO.FileMode]::OpenOrCreate})}
            Mock Get-RecoveryLockObject {$null=Assert-FixturePath $Handle.Name;New-DescriptorObject 'O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)' $false 0 $false}
            Mock Open-RecoveryWrite {Open-FixtureStream $Path ([IO.FileMode]::CreateNew)}
            Mock Set-RecoveryBytes {Set-FixtureBytes $Stream $Bytes}
            Mock Flush-RecoveryWrite {Flush-FixtureStream $Stream}
            Mock Close-RecoveryWrite {Close-FixtureStream $Stream}
            Mock Publish-RecoveryFile {$data=ConvertFrom-Json (Read-FixtureText $Temporary);Publish-FixtureFile $Temporary $Committed;$script:events+=('Publish:'+$data.State)}
        }
        It 'absent default-shaped OutDir has intent before mutation and checked Applied before promotion' {
            Initialize-RecoveryStorage | Should -BeTrue
            $RecoveryContext.Promoted | Should -BeTrue
            $events | Should -Contain 'OutDirCreateAfterIntent'
            $record=(Read-RecoveryRecords $OutDir 'Storage').Items[0];$record.State | Should -Be 'Applied';$record.Ownership | Should -Be 'Created';$record.Revision | Should -Be 2;$record.Prior.Exists | Should -BeFalse
            $intentIndex=[array]::IndexOf($events,'Publish:Intent');$createIndex=[array]::IndexOf($events,'OutDirCreateAfterIntent');$appliedIndex=[array]::IndexOf($events,'Publish:Applied');$intentIndex | Should -BeLessThan $createIndex;$createIndex | Should -BeLessThan $appliedIndex
        }
        It 'later invocation rediscovers same root and immutable Prior' {
            $null=Initialize-RecoveryStorage;$root=$RecoveryContext.Root;$id=(Read-RecoveryRecords $OutDir 'Storage').Items[0].RecordId;Close-RecoverySession
            $null=New-RunState;Initialize-RecoveryStorage | Should -BeTrue;$RecoveryContext.Root | Should -Be $root;(Read-RecoveryRecords $OutDir 'Storage').Items[0].RecordId | Should -Be $id
        }
        It 'preexisting protected OutDir captures original before use' {
            New-FixtureDirectory $OutDir;$script:protectedPaths[$OutDir]=$true
            Initialize-RecoveryStorage | Should -BeTrue;$r=(Read-RecoveryRecords $OutDir 'Storage').Items[0];$r.Ownership | Should -Be 'Preexisting';$r.Prior.Exists | Should -BeTrue;$r.ChangedByRun | Should -BeFalse
        }
        It 'second session fails while first holds the same deterministic lock' {
            $null=Initialize-RecoveryStorage;$held=$RecoveryContext;$script:RecoveryContext=$null
            try {{Open-RecoverySession $OutDir} | Should -Throw;Should -Invoke New-RecoveryDirectory -ParameterFilter {$Path -eq $OutDir} -Times 1}
            finally {$script:RecoveryContext=$held}
        }
        It 'DryRun creates no storage/lock/records and Unlock creates none on absence' {
            $DryRun=$true;Initialize-RecoveryStorage | Should -BeTrue;Should -Invoke New-RecoveryDirectory -Times 0;Should -Invoke Open-RecoveryLock -Times 0
            $DryRun=$false;$Unlock=$true;Initialize-RecoveryStorage | Should -BeFalse;Should -Invoke New-RecoveryDirectory -Times 0;Should -Invoke Open-RecoveryLock -Times 0
        }
        It 'bootstrap refusal <Fault> makes zero OutDir mutation calls' -ForEach @(@{Fault='untrusted parent'},@{Fault='reparse parent'},@{Fault='preplanted child'},@{Fault='creation'},@{Fault='protection'},@{Fault='lock acquisition'},@{Fault='lock descriptor'}) {
            switch($Fault){
                'untrusted parent'{Mock Get-RecoveryObject -ParameterFilter {$Path -eq (Join-Path $systemFixture 'config')} {New-DescriptorObject 'O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x2;;;BU)'}}
                'reparse parent'{Mock Get-RecoveryObject -ParameterFilter {$Path -eq (Join-Path $systemFixture 'config')} {New-DescriptorObject -Attributes 1024}}
                'preplanted child'{$base=Join-Path $systemFixture 'config\HPCC4-Recovery';New-FixtureDirectory $base;Mock Get-RecoveryObject -ParameterFilter {$Path -eq (Join-Path $systemFixture 'config\HPCC4-Recovery')} {New-DescriptorObject 'O:BUG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'}}
                creation{Mock New-RecoveryDirectory {throw 'creation fault'}}
                protection{Mock Set-RecoveryProtection {throw 'protection fault'}}
                'lock acquisition'{Mock Open-RecoveryLock {throw 'lock fault'}}
                'lock descriptor'{Mock Get-RecoveryLockObject {throw 'descriptor fault'}}
            }
            {Initialize-RecoveryStorage} | Should -Throw;Should -Invoke New-RecoveryDirectory -ParameterFilter {$Path -eq $OutDir} -Times 0;Test-Path -LiteralPath $OutDir | Should -BeFalse
        }
        It 'storage interruption <Fault> retains rediscoverable evidence' -ForEach @(@{Fault='intent publication'},@{Fault='OutDir create'},@{Fault='OutDir protection'},@{Fault='observation'},@{Fault='applied publication'},@{Fault='promotion'}) {
            switch($Fault){
                'intent publication'{Mock Publish-RecoveryFile {throw 'intent publication fault'}}
                'OutDir create'{Mock New-RecoveryDirectory -ParameterFilter {$Path -eq $OutDir} {throw 'mutation fault'}}
                'OutDir protection'{Mock Set-RecoveryProtection -ParameterFilter {$Path -eq $OutDir} {throw 'protection fault'}}
                observation{Mock Get-RecoveryObject -ParameterFilter {$Path -eq $OutDir -and $protectedPaths.ContainsKey($OutDir)} {throw 'observation fault'}}
                'applied publication'{Mock Publish-RecoveryFile -ParameterFilter {(ConvertFrom-Json (Read-FixtureText $Temporary)).State -eq 'Applied'} {throw 'applied publication fault'}}
                promotion{Mock Confirm-RecoveryPromotion {throw 'promotion fault'}}
            }
            {Initialize-RecoveryStorage} | Should -Throw
            $root=$RecoveryContext.Root;Test-Path -LiteralPath $root | Should -BeTrue
            if($Fault -eq 'intent publication'){Should -Invoke New-RecoveryDirectory -ParameterFilter {$Path -eq $OutDir} -Times 0;@(Get-ChildItem -LiteralPath $root -Filter '*.pending').Count | Should -Be 1}
            else {$committed=@(Get-ChildItem -LiteralPath $root -Filter '*.json');$committed.Count | Should -Be 1;$record=ConvertFrom-Json (Read-FixtureText $committed[0].FullName);$record.State | Should -Be $(if($Fault -eq 'promotion'){'Applied'}else{'Intent'})}
            Close-RecoverySession
            if($Fault -ne 'promotion'){{Initialize-RecoveryStorage} | Should -Throw}
        }
        It 'changed OutDir object identity refuses automatic reuse and preserves original' {
            $null=Initialize-RecoveryStorage;$id=(Read-RecoveryRecords $OutDir 'Storage').Items[0].RecordId;Close-RecoverySession;$script:objectEpoch=2
            {Initialize-RecoveryStorage} | Should -Throw;(Read-RecoveryRecords $OutDir 'Storage').Items[0].RecordId | Should -Be $id
        }
        It 'creation collision retains Intent and never claims or protects the collided OutDir' {
            Mock New-RecoveryDirectory -ParameterFilter {$Path -eq $OutDir} {New-FixtureDirectory (Assert-FixturePath $Path);throw 'fixed collision refusal'}
            {Initialize-RecoveryStorage} | Should -Throw
            $r=(Read-RecoveryRecords $OutDir 'Storage').Items[0];$r.State | Should -Be 'Intent';$r.ResourceIdentity | Should -BeNullOrEmpty;$r.ChangedByRun | Should -BeFalse
            Should -Invoke Set-RecoveryProtection -ParameterFilter {$Path -eq $OutDir} -Times 0
            $RecoveryContext.Promoted | Should -BeFalse
        }
        It 'same-identity unchanged preexisting Intent is retired before a new original is captured' {
            New-FixtureDirectory $OutDir;$script:protectedPaths[$OutDir]=$true
            $null=Open-RecoverySession $OutDir;$object=Get-RecoveryObject $OutDir
            $old=New-FixtureRecord;$old.ResourceIdentity=$object.Identity;$old.Prior=@{Exists=$true;Sddl=$object.Acl.Sddl;Attributes=$object.Attributes;Identity=$object.Identity};$old.IntendedState=$null
            Write-RecoveryRecord $old;Close-RecoverySession;$null=New-RunState
            Initialize-RecoveryStorage | Should -BeTrue
            $items=(Read-RecoveryRecords $OutDir 'Storage').Items;$items.Count | Should -Be 2
            $retired=@($items | Where-Object RecordId -eq $old.RecordId);$retired.Count | Should -Be 1;$retired[0].State | Should -Be 'Restored';$retired[0].Revision | Should -Be 2
            @($items | Where-Object State -eq 'Applied').Count | Should -Be 1
        }
    }
}
