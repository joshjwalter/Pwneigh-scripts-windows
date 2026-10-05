Describe 'Accepted tools and ordered policy imports' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'FixtureSafety.ps1')
        Assert-DefinitionSource (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        . (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        function Invoke-WebRequest {[CmdletBinding()]param($Uri,$OutFile,[switch]$UseBasicParsing)throw 'Denied download'}
    }
    BeforeEach {
        $DryRun=$false;$Unlock=$false;$Cleanup=$false;$OutDir=Join-Path $TestDrive 'out';$ToolsDir=Join-Path $TestDrive 'tools'
        $ToolsZip='';$ToolsZipSha256='';$AvInstallerUrl='';$InstallSysmon=$false;$LgpoExe='';$DodGpoDir='';$DodGpoSelection=@()
        $null=New-RunState;$State.IsDC=$false;$script:RecoveryContext=$null
        Mock Invoke-WebRequest {throw 'Denied download'};Mock Write-Log {};Mock Lock-AdminOnlyAcl {};Mock Initialize-ProtectedDirectory {};Mock Initialize-OwnedToolDirectory {}
        Mock Copy-ProtectedInput {throw 'Denied copy'};Mock Open-ProtectedRecoveryFile {throw 'Denied file creation'}
        Mock Invoke-NativeLeaf {throw 'Denied native'};Mock Start-InstallerLeaf {throw 'Denied installer'}
        Mock Get-CurrentWindowsIdentity {throw 'Denied identity'};Mock Get-RecoveryObject {throw 'Denied object'}
        Mock Set-RecoveryProtection {throw 'Denied ACL'};Mock Get-TlsProtocol {[Net.SecurityProtocolType]::Tls12};Mock Set-TlsProtocol {}
        Mock Set-OwnedRegistryValue {throw 'Denied registry publication'};Mock Install-AcceptedSysmon {throw 'Denied Sysmon'}
        Mock Get-CanonicalFilePath {$Path};Mock Assert-NativeApproval {throw 'Unapproved tool'}
        Mock Get-DodGpoSelection {throw 'No approved selections'};Mock Stage-DodGpoInputs {throw 'Denied input staging'}
        Mock Save-LocalPolicyRecoveryRecord {throw 'Denied policy backup'};Mock Invoke-NativeCommand {throw 'Denied external use'}
    }
    It 'a failed requested archive blocks PATH/EULA/Sysmon/LGPO work while AV remains independent' {
        $ToolsZip='C:\failed.zip';$AvInstallerUrl='https://example.invalid/av.exe';$InstallSysmon=$true;$LgpoExe='C:\stale\LGPO.exe'
        Mock Expand-ToolsZip {$false};Mock Invoke-WebRequest {};Mock Approve-RoleExecutable -ParameterFilter {$Role -eq 'AV'} {$Path}
        Install-Tools;$State.ToolReadiness.Archive | Should -Be Failed;$State.ToolReadiness.AV | Should -Be Complete
        Should -Invoke Set-OwnedRegistryValue -Times 0;Should -Invoke Install-AcceptedSysmon -Times 0;Should -Invoke Copy-ProtectedInput -Times 0
        Should -Invoke Approve-RoleExecutable -Times 0 -ParameterFilter {$Role -eq 'LGPO'}
    }
    It 'accepted archive publishes separate readiness and uses its role directory' {
        $ToolsZip='C:\accepted.zip';$InstallSysmon=$true
        Mock Expand-ToolsZip {$true};Mock Set-OwnedRegistryValue {};Mock Install-AcceptedSysmon {$State.ToolReadiness.Sysmon='Complete'}
        Install-Tools;$State.ToolsInstalled | Should -BeTrue;$State.ToolReadiness.Archive | Should -Be Complete;$State.ToolReadiness.Sysmon | Should -Be Complete
        Should -Invoke Set-OwnedRegistryValue -Times 1 -ParameterFilter {$Name -eq 'Path' -and $Kind -eq 'AppendPath' -and $Value -eq $State.AcceptedToolsDir}
    }
    It 'tool storage failure prevents download and all publication' {
        $AvInstallerUrl='https://example.invalid/av.exe';Mock Initialize-OwnedToolDirectory {throw 'storage failure'}
        {Install-Tools} | Should -Throw;Should -Invoke Invoke-WebRequest -Times 0;Should -Invoke Set-OwnedRegistryValue -Times 0
    }
    Context 'Production GPO prerequisite and order' {
        BeforeEach {
            $DodGpoDir='C:\fixture\selected';$State.AcceptedLgpoPath='C:\fixture\role\LGPO.exe'
            $State.Preconditions.NativeApprovals[$State.AcceptedLgpoPath]=@{Role='LGPO';Digest=('a'*64);TrustPolicy='ValidSignature';ResourceIdentity=@{Policy='VolumeFileId';Value='fixture:1'}}
            $script:selection=@(@{Path='C:\fixture\one';Package='one';Version='1';Role='operator';Approval=@{Folder='one'}},@{Path='C:\fixture\two';Package='two';Version='1';Role='operator';Approval=@{Folder='two'}})
            Mock Get-DodGpoSelection {$script:selection};Mock Assert-NativeApproval {};Mock Stage-DodGpoInputs {$State.GpoInputRoot='C:\fixture\protected';$Selected}
            Mock Save-LocalPolicyRecoveryRecord {New-ReadResult 'Complete' @(@{SchemaVersion=1;Kind='LocalPolicy';State='Applied';ResourceIdentity=@{Policy='VolumeFileId';Value='fixture'};Artifact=@{CanonicalPath='C:\fixture\manifest';Digest=('a'*64);Complete=$true}})}
            Mock Test-PolicyBackupManifest {};Mock Get-TrustedNativePath {'C:\fixture\gpupdate.exe'}
            Mock Get-PostGpoPolicyObservation {New-ReadResult 'Complete'}
        }
        It 'checked local backup precedes ordered imports and refresh' {
            $script:order=@();Mock Save-LocalPolicyRecoveryRecord {$script:order+='backup';New-ReadResult 'Complete' @(@{SchemaVersion=1;Kind='LocalPolicy';State='Applied';ResourceIdentity=@{Policy='VolumeFileId';Value='fixture'};Artifact=@{CanonicalPath='C:\fixture\manifest';Digest=('a'*64);Complete=$true}})}
            Mock Invoke-NativeCommand {if($Arguments[0] -eq '/g'){$script:order+=$Arguments[1]}else{$script:order+='refresh'};[pscustomobject]@{ExitCode=0;Output=@()}}
            Install-DodGpo;$order | Should -Be @('backup','C:\fixture\one','C:\fixture\two','refresh');$State.GpoApplied.Count | Should -Be 2
        }
        It 'incomplete backup prevents every import' {Mock Save-LocalPolicyRecoveryRecord {New-ReadResult 'Failed'};{Install-DodGpo} | Should -Throw;Should -Invoke Invoke-NativeCommand -Times 0}
        It 'partial import keeps errors, attempts independent approved inputs, and observes resultant policy' {
            Mock Invoke-NativeCommand {if($Arguments[0] -eq '/g' -and $Arguments[1] -eq 'C:\fixture\one'){throw 'first failed'};[pscustomobject]@{ExitCode=0;Output=@()}}
            Install-DodGpo;$State.GpoApplied | Should -Be @('C:\fixture\two');$State.Failures.Count | Should -BeGreaterThan 0;Should -Invoke Get-PostGpoPolicyObservation -Times 1
        }
        It 'dry-run validates selection/role but performs no staging, backup or import' {$DryRun=$true;Install-DodGpo;Should -Invoke Stage-DodGpoInputs -Times 0;Should -Invoke Save-LocalPolicyRecoveryRecord -Times 0;Should -Invoke Invoke-NativeCommand -Times 0}
    }
}

Describe 'Raw registry originals without host registry access' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'FixtureSafety.ps1')
        Assert-DefinitionSource (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        . (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
    }
    BeforeEach {
        $script:registryFake=[pscustomobject]@{Kind='Binary';Value=[byte[]]@(0,128,255);Disposed=$false;Written=$null;WrittenKind=$null}
        $registryFake | Add-Member ScriptMethod GetValueNames {,@('fixture')}
        $registryFake | Add-Member ScriptMethod GetValueKind {param($name)[Microsoft.Win32.RegistryValueKind]$this.Kind}
        $registryFake | Add-Member ScriptMethod GetValue {param($name,$default,$options);if($options -ne [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames){throw 'Expansion forbidden'};return ,$this.Value}
        $registryFake | Add-Member ScriptMethod SetValue {param($name,$value,$kind);$this.Written=$value;$this.WrittenKind=$kind}
        $registryFake | Add-Member ScriptMethod Dispose {$this.Disposed=$true}
        Mock Test-Path {if($LiteralPath -ne 'HKCU:\FixtureOnly'){throw 'Unexpected registry path'};$true}
        Mock Get-Item {if($LiteralPath -ne 'HKCU:\FixtureOnly'){throw 'Unexpected registry path'};$script:registryFake}
        Mock New-Item {throw 'Denied registry creation'}
        Mock Remove-ItemProperty {throw 'Denied registry deletion'}
    }
    It 'binary originals survive journal conversion and restore as exact bytes' {
        $prior=Get-RawRegistryValue 'HKCU:\FixtureOnly' 'fixture'
        $prior.Kind | Should -Be Binary;$prior.Value | Should -Be @([int]0,[int]128,[int]255)
        $registryFake.Disposed | Should -BeTrue
        $json=ConvertTo-Json -InputObject (ConvertTo-RecoveryData $prior) -Depth 8
        $restored=ConvertTo-RecoveryData (ConvertFrom-Json $json) -FromJson
        Set-RawRegistryValue 'HKCU:\FixtureOnly' 'fixture' $restored
        $registryFake.Written.GetType().FullName | Should -Be 'System.Byte[]'
        $registryFake.Written | Should -Be @([byte]0,[byte]128,[byte]255)
        $registryFake.WrittenKind | Should -Be Binary
    }
    It 'multi-string members and unexpanded strings remain exact' {
        $registryFake.Kind='MultiString';$registryFake.Value=[string[]]@('%TEMP%','second','')
        $prior=Get-RawRegistryValue 'HKCU:\FixtureOnly' 'fixture'
        $roundtrip=ConvertTo-RecoveryData (ConvertFrom-Json (ConvertTo-Json -InputObject (ConvertTo-RecoveryData $prior) -Depth 8)) -FromJson
        Set-RawRegistryValue 'HKCU:\FixtureOnly' 'fixture' $roundtrip
        $registryFake.Written.GetType().FullName | Should -Be 'System.String[]'
        $registryFake.Written | Should -Be @('%TEMP%','second','')
        $registryFake.Kind='ExpandString';$registryFake.Value='%SystemRoot%\fixture'
        (Get-RawRegistryValue 'HKCU:\FixtureOnly' 'fixture').Value | Should -Be '%SystemRoot%\fixture'
    }
}

Describe 'Actual GPO manifest validation on bounded fixtures' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'FixtureSafety.ps1')
        Assert-DefinitionSource (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
        . (Join-Path $PSScriptRoot '..\hpcc4-simple.ps1')
    }
    BeforeEach {
        $script:gpoRoot=Join-Path $TestDrive 'gpo';New-FixtureDirectory $gpoRoot
        $script:choices=@()
        foreach($name in 'one','two'){
            $folder=Join-Path $gpoRoot $name;New-FixtureDirectory $folder
            New-FixtureDirectory (Join-Path $folder 'DomainSysvol\GPO\Machine')
            Write-FixtureText (Join-Path $folder 'Backup.xml') '<GroupPolicyBackupScheme />'
            Write-FixtureText (Join-Path $folder 'DomainSysvol\GPO\Machine\registry.pol') 'fixture-only'
            $files=@{};foreach($relative in 'Backup.xml','DomainSysvol/GPO/Machine/registry.pol'){
                $safe=Assert-FixturePath (Join-Path $folder $relative);$sha=[Security.Cryptography.SHA256]::Create()
                try{$files[$relative]=-join($sha.ComputeHash([IO.File]::ReadAllBytes($safe)) | ForEach-Object {$_.ToString('x2')})}finally{$sha.Dispose()}
            }
            $script:choices+=@{Folder=$name;Package='fixture';Version='1';Role='operator-selected';Approved=$true;Files=$files}
        }
        Mock Get-Item {Get-FixtureItem $LiteralPath}
        Mock Get-ChildItem {Get-FixtureEntries $LiteralPath}
        Mock Get-FileHash {
            $safe=Assert-FixturePath $LiteralPath;$sha=[Security.Cryptography.SHA256]::Create()
            try{[pscustomobject]@{Hash=(-join($sha.ComputeHash([IO.File]::ReadAllBytes($safe)) | ForEach-Object {$_.ToString('x2')}))}}finally{$sha.Dispose()}
        }
        Mock Invoke-NativeLeaf {throw 'Denied native'}
    }
    It 'validates actual payloads and returns exactly the explicit order' {
        $items=@(Get-DodGpoSelection $gpoRoot @($choices[1],$choices[0]))
        $items.Count | Should -Be 2;$items[0].Path | Should -Be (Join-Path $gpoRoot 'two');$items[1].Approval.Folder | Should -Be one
    }
    It 'refuses later changed bytes and undeclared extra payloads' {
        Write-FixtureText (Join-Path $gpoRoot 'two\Backup.xml') '<GroupPolicyBackupScheme changed="1" />'
        {Get-DodGpoSelection $gpoRoot $choices} | Should -Throw
        Write-FixtureText (Join-Path $gpoRoot 'one\extra.ps1') 'fixture-only'
        {Get-DodGpoSelection $gpoRoot @($choices[0])} | Should -Throw
        Should -Invoke Invoke-NativeLeaf -Times 0
    }
    It 'refuses duplicate selections and unapproved package metadata' {
        {Get-DodGpoSelection $gpoRoot @($choices[0],$choices[0])} | Should -Throw
        $choices[0].Approved=$false;{Get-DodGpoSelection $gpoRoot @($choices[0])} | Should -Throw
    }
}
