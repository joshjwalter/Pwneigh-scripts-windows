Describe 'B runtime contracts (fixture only)' {
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
        Mock Initialize-ObjectIdentityApi {throw 'Forbidden native/CLR API initialization'}
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

    It 'managed output is one Boolean and does not touch global status' {
        $prior=Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue; $value=if($prior){$prior.Value}else{$null}
        try { $global:LASTEXITCODE=77; $r=@(Invoke-Step 'managed' { 'incidental';42 }); $r.Count | Should -Be 1; $r[0] | Should -BeTrue; $global:LASTEXITCODE | Should -Be 77 }
        finally { if($prior){$global:LASTEXITCODE=$value}else{Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue} }
    }
    It 'wrapped cancellation escapes ordinary work' {
        { Invoke-Step 'cancel' { throw [InvalidOperationException]::new('wrapped',[OperationCanceledException]::new()) } } | Should -Throw
        $State.Cancelled | Should -BeTrue
    }
    It 'emitted error is one false' { $r=@(Invoke-Step 'error' { Write-Error 'fixture';'extra' }); $r.Count | Should -Be 1; $r[0] | Should -BeFalse; $State.Failures.Count | Should -Be 1 }
    It 'ordinary thrown errors and reporting errors retain the Boolean contract' {
        Mock Write-Log { throw 'log failure' }
        $r=@(Invoke-Step 'error' { throw 'fixture' }); $r.Count | Should -Be 1; $r[0] | Should -BeFalse; $State.Failures.Count | Should -Be 2
        $r=@(Invoke-Step 'ok' {42}); $r.Count | Should -Be 1; $r[0] | Should -BeTrue; $State.Failures.Count | Should -Be 3
    }
    It 'Stage consumes output and continues independent ordinary work' {
        @(Invoke-Stage 'first' {'extra';throw 'failure'}).Count | Should -Be 0
        @(Invoke-Stage 'second' {'extra'}).Count | Should -Be 0
        $State.Failures.Count | Should -Be 1
    }
    It 'DryRun never invokes the action and emits one false' { $DryRun=$true; $script:called=0; $r=@(Invoke-Step 'dry' {$script:called++}); $r.Count | Should -Be 1; $r[0] | Should -BeFalse; $script:called | Should -Be 0 }
    It 'State is fresh with no profile authority' { $old=$State; $new=New-RunState; [object]::ReferenceEquals($old,$new) | Should -BeFalse; $new.Preconditions.RecoveryEligible | Should -BeFalse; $new.Preconditions.RecoveryPlan.ProfileOperations.Count | Should -Be 0 }
    It 'canonical equality preserves types and array cardinality <Label>' -ForEach @(
        @{Label='string/singleton integer';Left='1';Right=@(1)}, @{Label='null/empty';Left=$null;Right=@()}, @{Label='scalar/singleton';Left=1;Right=@(1)}, @{Label='empty/single null';Left=@();Right=@($null)}, @{Label='one/two';Left=@(1);Right=@(1,1)}, @{Label='nested/scalar';Left=@{a=@(1)};Right=@{a=1}}
    ) { Test-DataEqual $Left $Right | Should -BeFalse }
    It 'dictionary ordering has stable equality' { Test-DataEqual @{a=1;b=@('x','y')} @{b=@('x','y');a=1} | Should -BeTrue }
    It 'owned fake handle disposal failure is recorded and context cleared' {
        $handle=[pscustomobject]@{} | Add-Member ScriptMethod Dispose {throw 'fixture release fault'} -PassThru
        $script:RecoveryContext=@{Handle=$handle}
        @(Close-RecoverySession).Count | Should -Be 0
        $RecoveryContext | Should -BeNullOrEmpty
        $State.RecoveryStatus | Should -Be 'Partial';$State.Failures.Operation | Should -Contain 'ReleaseLock'
    }
    It 'unsupported engine <Edition>/<Version> refuses before storage or ordinary work' -ForEach @(@{Edition='Core';Version='7.4'},@{Edition='Desktop';Version='5.0'}) {
        Mock Get-RuntimeEngineInfo {[pscustomobject]@{Edition=$Edition;Version=[version]$Version;Is64Bit=$true;Platform='Win32NT'}}
        $r=Main;$r.Status | Should -Be 'Failed';$r.State.Preconditions.RecoveryEligible | Should -BeFalse
        Should -Invoke Open-RecoveryLock -Times 0;Should -Invoke New-RecoveryDirectory -Times 0;Should -Invoke Backup-Targets -Times 0
    }

    Context 'native wrapper with default denied leaf' {
        BeforeEach { Mock Assert-NativeApproval {}; $script:nativePath='C:\fixture\native.exe' }
        It 'restores global <GlobalState> with <OutputCount> outputs' -ForEach @(
            @{GlobalState='absent';OutputCount=0},@{GlobalState='null';OutputCount=1},@{GlobalState='prior';OutputCount=2}
        ) {
            $saved=Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue; $value=if($saved){$saved.Value}else{$null}
            try {
                if($GlobalState -eq 'absent'){Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue}elseif($GlobalState -eq 'null'){$global:LASTEXITCODE=$null}else{$global:LASTEXITCODE=77}
                Mock Invoke-NativeLeaf { $global:LASTEXITCODE=0; for($i=0;$i -lt $OutputCount;$i++){"row$i"} }
                $r=@(Invoke-NativeCommand $nativePath @('fixed')); $r.Count | Should -Be 1; $r[0].Output -is [object[]] | Should -BeTrue; $r[0].Output.Count | Should -Be $OutputCount
                $v=Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
                if($GlobalState -eq 'absent'){$v | Should -BeNullOrEmpty}elseif($GlobalState -eq 'null'){$v.Value | Should -BeNullOrEmpty}else{$v.Value | Should -Be 77}
            } finally {if($saved){$global:LASTEXITCODE=$value}else{Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue}}
        }
        It 'accepts explicit exits <Code> only under <Codes>' -ForEach @(@{Code=0;Codes=@(0);Ok=$true},@{Code=7;Codes=0..7;Ok=$true},@{Code=8;Codes=0..7;Ok=$false},@{Code=16;Codes=@(0);Ok=$false}) {
            Mock Invoke-NativeLeaf {$global:LASTEXITCODE=[int]$Code}
            if($Ok){(Invoke-NativeCommand $nativePath @('fixed') $Codes).ExitCode | Should -Be $Code}else{{Invoke-NativeCommand $nativePath @('fixed') $Codes} | Should -Throw}
        }
        It 'fails launch/genuine PowerShell error even with zero global' -ForEach @(@{Form='throw'},@{Form='emitted'}) {
            Mock Invoke-NativeLeaf {if($Form -eq 'throw'){throw 'launch'}else{Write-Error 'managed failure'}}
            {Invoke-NativeCommand $nativePath @('fixed')} | Should -Throw
        }
        It 'allows authentic native stderr diagnostic objects and preserves order' {
            Mock Invoke-NativeLeaf { 'before'; [Management.Automation.ErrorRecord]::new([Management.Automation.RemoteException]::new('diagnostic'),'NativeCommandError',[Management.Automation.ErrorCategory]::NotSpecified,$null); 'after'; $global:LASTEXITCODE=0 }
            $r=Invoke-NativeCommand $nativePath @('fixed'); $r.Output.Count | Should -Be 3; $r.Output[0] | Should -Be 'before'; $r.Output[1] -is [Management.Automation.ErrorRecord] | Should -BeTrue; $r.Output[2] | Should -Be 'after'
        }
        It 'preserves strict caller preferences and local/script shadows' {
            $script:LASTEXITCODE=91
            try {
                Mock Invoke-NativeLeaf {$global:LASTEXITCODE=0}
                & { $LASTEXITCODE=92; $ErrorActionPreference='Stop'; $PSNativeCommandUseErrorActionPreference=$true; $PSNativeCommandArgumentPassing='Legacy'; $r=Invoke-NativeCommand $nativePath @('fixed'); $LASTEXITCODE | Should -Be 92; $ErrorActionPreference | Should -Be 'Stop'; $PSNativeCommandUseErrorActionPreference | Should -BeTrue; $PSNativeCommandArgumentPassing | Should -Be 'Legacy' }
                $script:LASTEXITCODE | Should -Be 91
            } finally {Remove-Variable LASTEXITCODE -Scope Script -ErrorAction SilentlyContinue}
        }
        It 'nested calls restore the outer explicit global scalar' {
            Mock Invoke-NativeLeaf {if($Arguments[0] -eq 'outer'){$global:LASTEXITCODE=19; $null=Invoke-NativeCommand $nativePath @('inner'); $global:LASTEXITCODE | Should -Be 19};$global:LASTEXITCODE=0}
            (Invoke-NativeCommand $nativePath @('outer')).ExitCode | Should -Be 0
        }
        It 'read-only global refuses before native launch' {
            $v=Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue; $value=if($v){$v.Value}else{$null}
            try {Set-Variable LASTEXITCODE -Scope Global -Value 77 -Option ReadOnly; {Invoke-NativeCommand $nativePath @('fixed')} | Should -Throw; Should -Invoke Invoke-NativeLeaf -Times 0}
            finally {Set-Variable LASTEXITCODE -Scope Global -Option None -Force; if($v){$global:LASTEXITCODE=$value}else{Remove-Variable LASTEXITCODE -Scope Global}}
        }
        It 'refuses unsupported arguments <Label> before launch' -ForEach @(@{Label='empty';Argument=''},@{Label='embedded quote';Argument='a"b'},@{Label='nul';Argument="a$([char]0)b"}) { {Invoke-NativeCommand $nativePath @($Argument)} | Should -Throw; Should -Invoke Invoke-NativeLeaf -Times 0 }
        It 'first essential failure prevents the second command' {
            Mock Invoke-NativeLeaf {$global:LASTEXITCODE=8}
            Invoke-Step 'compound' {$null=Invoke-NativeCommand $nativePath @('first'); $null=Invoke-NativeCommand $nativePath @('second')} | Should -BeFalse
            Should -Invoke Invoke-NativeLeaf -Times 1
        }
        It 'native failure preserves sanitized status/classification/order without diagnostic text' {
            Mock Invoke-NativeLeaf {'secret fixture output';42;$global:LASTEXITCODE=8}
            $caught=$null;try{$null=Invoke-NativeCommand $nativePath @('secret argument')}catch{$caught=$_}
            $caught | Should -Not -BeNullOrEmpty
            $caught.TargetObject.ExitCode | Should -Be 8;$caught.TargetObject.Classification | Should -Be 'UnacceptableExit'
            $caught.TargetObject.Diagnostics.Index | Should -Be @(0,1)
            ($caught | Out-String) | Should -Not -Match 'secret'
        }
        It 'failed global restoration emits no partial success result' {
            $v=Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue;$value=if($v){$v.Value}else{$null}
            try {
                $global:LASTEXITCODE=77;Mock Invoke-NativeLeaf {$global:LASTEXITCODE=0;'fixed'}
                Mock Set-Variable -ParameterFilter {$Name -eq 'LASTEXITCODE' -and $Scope -eq 'Global' -and $Value -eq 77} {throw 'fixture restore fault'}
                $r=@();$caught=$null;try{$r=@(Invoke-NativeCommand $nativePath @('fixed'))}catch{$caught=$_}
                $r.Count | Should -Be 0;$caught.TargetObject.Classification | Should -Be 'GlobalRestoreFailure'
            } finally {if($v){$global:LASTEXITCODE=$value}else{Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue}}
        }
        It 'ambiguous trailing separator with whitespace refuses before launch' { {Invoke-NativeCommand $nativePath @('C:\space dir\')} | Should -Throw;Should -Invoke Invoke-NativeLeaf -Times 0 }
    }

    Context 'Main orchestration' {
        BeforeEach {
            Mock Assert-SupportedEngine {}; Mock Test-IsAdmin {$true}; Mock Get-RuntimeRole {3}; Mock Get-RuntimeRdpPort {3389}
            Mock Get-TrustedNativePath {"C:\fixture\$Name"}
            Mock Initialize-Setup {$true}
            foreach ($stage in 'Backup-Targets','Set-FirewallLockdown','Remove-UnauthorizedUsers','Set-LocalPasswords','Disable-ExtraServices','Get-PersistenceReport','Install-DodGpo','Install-Tools','Lock-Paths','Unlock-Paths','Invoke-Cleanup','Write-Summary','Add-Rule') {Mock $stage {'incidental'}}
        }
        It 'returns exactly one result and installs a fresh State on every run' {$a=@(Main);$b=@(Main);$a.Count | Should -Be 1;$b.Count | Should -Be 1;$a[0].Status | Should -Be 'Succeeded';[object]::ReferenceEquals($a[0].State,$b[0].State) | Should -BeFalse}
        It 'ordinary body and recovery failures both survive' {Mock Backup-Targets {throw 'body'};Mock Add-Rule {throw 'recovery'};$r=Main;$r.Status | Should -Be 'Failed';@($r.Failures | Where-Object Stage -eq 'Backup').Count | Should -Be 1;@($r.Failures | Where-Object Stage -eq 'RecoveryRule').Count | Should -BeGreaterThan 0;Should -Invoke Install-Tools -Times 1}
        It 'cancellation stops subsequent domain and cleanup work' {Mock Set-LocalPasswords {throw [InvalidOperationException]::new('wrapped',[OperationCanceledException]::new())};$Cleanup=$true;$r=Main;$r.Status | Should -Be 'Cancelled';Should -Invoke Install-Tools -Times 0;Should -Invoke Invoke-Cleanup -Times 0}
        It 'early ordinary-stage cancellation starts no later account or tools work' {
            Mock Backup-Targets {throw [OperationCanceledException]::new()};$Cleanup=$true
            $r=Main;$r.Status | Should -Be 'Cancelled';Should -Invoke Remove-UnauthorizedUsers -Times 0;Should -Invoke Install-Tools -Times 0;Should -Invoke Invoke-Cleanup -Times 0
        }
        It 'normal finish with independently recorded failures still permits existing terminal decisions' {
            Mock Backup-Targets {throw 'ordinary body failure'};Mock Install-Tools {$script:State.AvInstaller='C:\fixture\approved-av.exe'}
            Mock Start-ApprovedInstaller {$true};$Cleanup=$true
            $r=Main;$r.Status | Should -Be 'Failed';Should -Invoke Start-ApprovedInstaller -Times 1;Should -Invoke Invoke-Cleanup -Times 1
        }
        It 'cooperative cancellation at <Boundary> returns one Cancelled result and releases context' -ForEach @(@{Boundary='recovery'},@{Boundary='summary'},@{Boundary='release'}) {
            $releaseCounter=@{Calls=0};$Cleanup=$true
            $handle=[pscustomobject]@{Counter=$releaseCounter} | Add-Member ScriptMethod Dispose {$this.Counter.Calls++} -PassThru
            if($Boundary -eq 'release'){$handle=[pscustomobject]@{Counter=$releaseCounter} | Add-Member ScriptMethod Dispose {$this.Counter.Calls++;throw [InvalidOperationException]::new('wrapped',[OperationCanceledException]::new())} -PassThru}
            Mock Initialize-Setup {$script:RecoveryContext=@{Handle=$handle};$true}
            if($Boundary -eq 'recovery'){Mock Add-Rule {throw [InvalidOperationException]::new('wrapped',[OperationCanceledException]::new())}}
            if($Boundary -eq 'summary'){Mock Write-Summary {throw [OperationCanceledException]::new()}}
            $r=@(Main);$r.Count | Should -Be 1;$r[0].Status | Should -Be 'Cancelled';$r[0].State.Cancelled | Should -BeTrue
            $releaseCounter.Calls | Should -Be 1;$RecoveryContext | Should -BeNullOrEmpty
            if($Boundary -eq 'recovery'){Should -Invoke Invoke-Cleanup -Times 0;Should -Invoke Write-Summary -Times 0}
        }
        It 'failed preflight <Fault> performs zero mutator/stage calls, including finally' -ForEach @(@{Fault='admin'},@{Fault='port'},@{Fault='path'},@{Fault='role'},@{Fault='conflicting modes'},@{Fault='firewall'},@{Fault='listeners'},@{Fault='accounts'}) {
            switch($Fault){admin{Mock Test-IsAdmin {$false}} port{$AllowTcp=@(70000)} path{$OutDir='HKLM:\bad'} role{Mock Get-RuntimeRole {$null}} 'conflicting modes'{$Unlock=$true;$Cleanup=$true} firewall{Mock Get-FirewallSnapshot {New-ReadResult 'Failed'}} listeners{Mock Get-ListeningPorts {New-ReadResult 'Failed'}} accounts{Mock Get-AccountSnapshot {New-ReadResult 'Failed'}}}
            $r=Main;$r.Status | Should -Be 'Failed';$State.Preconditions.RecoveryEligible | Should -BeFalse;Should -Invoke Initialize-Setup -Times 0;Should -Invoke Add-Rule -Times 0;Should -Invoke Set-NetFirewallProfile -Times 0;Should -Invoke Remove-UnauthorizedUsers -Times 0
        }
        It 'required inbox trust failure stops before storage and all ordinary and terminal work' {
            Mock Get-TrustedNativePath {throw 'fixed trust refusal'};$Cleanup=$true
            $r=Main;$r.Status | Should -Be 'Failed';$r.State.Preconditions.RecoveryEligible | Should -BeFalse
            Should -Invoke Initialize-Setup -Times 0;Should -Invoke Backup-Targets -Times 0;Should -Invoke Add-Rule -Times 0;Should -Invoke Invoke-Cleanup -Times 0
        }
        It 'reader cancellation at setup stops later ordinary and terminal work' {
            Mock Initialize-Setup {throw [OperationCanceledException]::new()};$Cleanup=$true
            $r=Main;$r.Status | Should -Be 'Cancelled';$r.State.Cancelled | Should -BeTrue
            Should -Invoke Backup-Targets -Times 0;Should -Invoke Remove-UnauthorizedUsers -Times 0;Should -Invoke Install-Tools -Times 0;Should -Invoke Invoke-Cleanup -Times 0
        }
        It 'setup failure cannot invent profile authority or enter AV/cleanup' {Mock Initialize-Setup {$false};$Cleanup=$true;$r=Main;$r.Status | Should -Be 'Failed';Should -Invoke Set-NetFirewallProfile -Times 0;Should -Invoke Install-Tools -Times 0;Should -Invoke Invoke-Cleanup -Times 0}
        It 'Unlock needs no role/RDP and enters no firewall recovery' {$Unlock=$true;$r=Main;$r.Status | Should -Be 'Succeeded';Should -Invoke Get-RuntimeRole -Times 0;Should -Invoke Get-RuntimeRdpPort -Times 0;Should -Invoke Add-Rule -Times 0;Should -Invoke Set-FirewallLockdown -Times 0;Should -Invoke Unlock-Paths -Times 1}
        It 'DryRun plus Unlock is valid' {$DryRun=$true;$Unlock=$true;(Main).Status | Should -Be 'DryRun';Should -Invoke Add-Rule -Times 0}
        It 'lock lifetime includes terminal cleanup and report' {
            $Cleanup=$true;$script:closed=$false
            Mock Close-RecoverySession {$script:closed=$true};Mock Invoke-Cleanup {$script:closed | Should -BeFalse};Mock Write-Summary {$script:closed | Should -BeFalse}
            $null=Main;$script:closed | Should -BeTrue
        }
        It 'ordinary body, recovery and release failures remain in one cooperative result' {
            Mock Backup-Targets {throw 'body'};Mock Add-Rule {throw 'recovery'}
            Mock Initialize-Setup {$script:RecoveryContext=@{Handle=([pscustomobject]@{} | Add-Member ScriptMethod Dispose {throw 'release'} -PassThru)};$true}
            $r=@(Main);$r.Count | Should -Be 1;$r[0].Status | Should -Be 'Failed';$r[0].Failures.Operation | Should -Contain 'ReleaseLock';$r[0].RecoveryStatus | Should -Be 'Partial';$RecoveryContext | Should -BeNullOrEmpty
        }
        It 'mutation-rich fake stages in DryRun do not invoke mutators or claim actual recovery' {
            $DryRun=$true;$script:mutatorCalls=0
            foreach($name in 'Backup-Targets','Set-FirewallLockdown','Remove-UnauthorizedUsers','Set-LocalPasswords','Disable-ExtraServices','Get-PersistenceReport','Install-DodGpo','Install-Tools','Lock-Paths','Add-Rule'){Mock $name {$null=Invoke-Step 'fixture mutator' {$script:mutatorCalls++}}}
            $r=Main;$r.Status | Should -Be 'DryRun';$r.RecoveryStatus | Should -Be 'Planned';$mutatorCalls | Should -Be 0;$r.State.Operations.Count | Should -BeGreaterThan 5
        }
    }

    Context 'protected journal fixture IO' {
        BeforeEach {
            New-FixtureDirectory $OutDir
            $script:journal=Join-Path $TestDrive ([guid]::NewGuid().ToString());New-FixtureDirectory $journal
            $script:fixtureHandle=Open-FixtureStream (Join-Path $journal 'writer.lock') ([IO.FileMode]::OpenOrCreate)
            $script:RecoveryContext=@{Root=$journal;OutDir=$OutDir;MachineId='11111111-1111-1111-1111-111111111111';Handle=$fixtureHandle;Promoted=$false}
            Mock Assert-TrustedPath {} # descriptors tested separately, IO stays in TestDrive
            Mock Open-RecoveryWrite { if(-not (Test-PathWithin $Path $journal)){throw 'Fixture boundary'};Open-FixtureStream $Path ([IO.FileMode]::CreateNew) }
            Mock Set-RecoveryBytes {Set-FixtureBytes $Stream $Bytes}
            Mock Flush-RecoveryWrite {Flush-FixtureStream $Stream}
            Mock Close-RecoveryWrite {Close-FixtureStream $Stream}
            Mock Publish-RecoveryFile {if(-not(Test-PathWithin $Temporary $journal) -or -not(Test-PathWithin $Committed $journal)){throw 'Fixture boundary'};Publish-FixtureFile $Temporary $Committed}
        }
        It 'ReadResult zero/single/multiple Items are arrays' {
            $r=Read-RecoveryRecords $OutDir;$r.Status | Should -Be 'Absent';$r.Items -is [object[]] | Should -BeTrue;$r.Items.Count | Should -Be 0
            $one=New-FixtureRecord;@(Write-RecoveryRecord $one).Count | Should -Be 0;$r=Read-RecoveryRecords $OutDir;$r.Items.Count | Should -Be 1;$r.Items[0] -is [hashtable] | Should -BeTrue
            $two=New-FixtureRecord;$two.ResourceId='second';Write-RecoveryRecord $two;$r=Read-RecoveryRecords $OutDir;$r.Items.Count | Should -Be 2;$r.Items -is [object[]] | Should -BeTrue
        }
        It 'Prior is immutable and revisions monotonic' {
            $record=New-FixtureRecord;Write-RecoveryRecord $record;$record.State='Applied';$record.AppliedObservation=@{Value='checked'};$record.Revision=2;Write-RecoveryRecord $record
            {Write-RecoveryRecord $record} | Should -Throw
            $record.Revision=3;$record.Prior.Value='new';{Write-RecoveryRecord $record} | Should -Throw
            (Read-RecoveryRecords $OutDir).Items[0].Prior.Value | Should -Be 'original'
        }
        It 'duplicate active resource refuses instead of replacing Prior' {$a=New-FixtureRecord;Write-RecoveryRecord $a;$b=New-FixtureRecord;{Write-RecoveryRecord $b} | Should -Throw;(Read-RecoveryRecords $OutDir).Items.Count | Should -Be 1}
        It 'unknown/malformed metadata returns unhealthy <Form>' -ForEach @(@{Form='unknown file'},@{Form='malformed json'},@{Form='duplicate active'},@{Form='schema'}) {
            $a=New-FixtureRecord;Write-RecoveryRecord $a
            switch($Form){'unknown file'{Write-FixtureText (Join-Path $journal 'unknown.pending') 'x'} 'malformed json'{Write-FixtureText (Join-Path $journal ([guid]::NewGuid().ToString()+'.json')) '{'} 'duplicate active'{$b=New-FixtureRecord;Write-FixtureText (Join-Path $journal ($b.RecordId+'.json')) ($b | ConvertTo-Json -Depth 20)} schema{$b=New-FixtureRecord;$b.SchemaVersion=2;Write-FixtureText (Join-Path $journal ($b.RecordId+'.json')) ($b | ConvertTo-Json -Depth 20)}}
            (Read-RecoveryRecords $OutDir).Status | Should -Be 'Partial';{Write-RecoveryRecord (New-FixtureRecord)} | Should -Throw
        }
        It 'publication fault <Boundary> retains old committed evidence and reports interruption' -ForEach @(@{Boundary='open'},@{Boundary='write'},@{Boundary='flush'},@{Boundary='close'},@{Boundary='replace'}) {
            $a=New-FixtureRecord;Write-RecoveryRecord $a;$a.State='Applied';$a.Revision=2;$a.AppliedObservation=@{Value='checked'}
            switch($Boundary){open{Mock Open-RecoveryWrite {throw 'create fault'}} write{Mock Set-RecoveryBytes {throw 'write fault'}} flush{Mock Flush-RecoveryWrite {throw 'flush fault'}} close{Mock Close-RecoveryWrite {Close-FixtureStream $Stream;throw 'close fault'}} replace{Mock Publish-RecoveryFile {throw 'replace fault'}}}
            {Write-RecoveryRecord $a} | Should -Throw
            $old=ConvertFrom-Json ((Read-FixtureText (Join-Path $journal ($a.RecordId+'.json'))));$old.Revision | Should -Be 1;$old.State | Should -Be 'Intent'
            if($Boundary -ne 'open'){(Read-RecoveryRecords $OutDir).Status | Should -Be 'Partial'}
        }
        It 'second exclusive opener fails and releasing the handle preserves the file' { { Open-FixtureStream (Join-Path $journal 'writer.lock') ([IO.FileMode]::Open) } | Should -Throw;Close-RecoverySession;Test-Path (Join-Path $journal 'writer.lock') | Should -BeTrue;$h=Open-FixtureStream (Join-Path $journal 'writer.lock') ([IO.FileMode]::Open);Close-FixtureStream $h }
        It 'restart Intent evaluates exact prior/intended and refuses unknown identity' {
            $a=New-FixtureRecord;Get-IntentRecoveryDisposition $a $a.ResourceIdentity $a.Prior | Should -Be 'NoChange';Get-IntentRecoveryDisposition $a $a.ResourceIdentity $a.IntendedState | Should -Be 'ExactIntendedState';Get-IntentRecoveryDisposition $a @{Policy='VolumeFileId';Value='replacement'} $a.Prior | Should -Be 'Unknown';Get-IntentRecoveryDisposition $a $a.ResourceIdentity @{Value='other'} | Should -Be 'Unknown';$a.ResourceIdentity=$null;Get-IntentRecoveryDisposition $a @{} $a.Prior | Should -Be 'Unknown'
        }
        It 'DryRun writer performs no IO' {$DryRun=$true;Write-RecoveryRecord (New-FixtureRecord);Should -Invoke Open-RecoveryWrite -Times 0;(Read-RecoveryRecords $OutDir).Status | Should -Be 'Absent'}
        It 'reader cancellation <Boundary> is rethrown and marked' -ForEach @(@{Boundary='outer'},@{Boundary='inner'}) {
            $a=New-FixtureRecord;Write-RecoveryRecord $a
            if($Boundary -eq 'outer'){Mock Get-ChildItem {throw [OperationCanceledException]::new()}}else{Mock Get-Content {throw [InvalidOperationException]::new('wrapped',[OperationCanceledException]::new())}}
            {Read-RecoveryRecords $OutDir} | Should -Throw;$State.Cancelled | Should -BeTrue
        }
        It 'noncanonical GUID <Field>/<Form> refuses before writing' -ForEach @(
            @{Field='RecordId';Form='N'},@{Field='RecordId';Form='B'},@{Field='RunId';Form='N'},@{Field='MachineId';Form='N'},@{Field='RecordId';Form='CLR'}
        ) {
            $a=New-FixtureRecord;if($Form -eq 'CLR'){$a[$Field]=[guid]::NewGuid()}else{$a[$Field]=[guid]::NewGuid().ToString($Form)}
            {Write-RecoveryRecord $a} | Should -Throw;Should -Invoke Open-RecoveryWrite -Times 0
        }
        It 'unsupported persisted scalar <Form> refuses before writing' -ForEach @(@{Form='date';Value=[datetime]::UtcNow},@{Form='enum';Value=[IO.FileAttributes]::Normal},@{Form='struct';Value=[guid]::NewGuid()},@{Form='decimal';Value=[decimal]1.25},@{Form='nonfinite';Value=[double]::NaN}) {
            $a=New-FixtureRecord;$a.Prior=@{Value=$Value};{Write-RecoveryRecord $a} | Should -Throw;Should -Invoke Open-RecoveryWrite -Times 0
        }
        It 'JSON round-trip preserves supported primitive types and array cardinality' {
            $a=New-FixtureRecord;$a.Prior=@{Null=$null;Boolean=$true;Text='1';Small=[int]1;Large=[long]2147483648;Real=[double]1.25;Empty=@();Singleton=@(1);Multiple=@(1,2);Nested=@{Value=@('x')}}
            Write-RecoveryRecord $a;$r=Read-RecoveryRecords $OutDir;$r.Status | Should -Be 'Complete';$b=$r.Items[0]
            $b.Revision -is [int] | Should -BeTrue;Test-DataEqual $a.Prior $b.Prior | Should -BeTrue
            $b.Prior.Empty -is [object[]] | Should -BeTrue;$b.Prior.Empty.Count | Should -Be 0;$b.Prior.Singleton.Count | Should -Be 1;$b.Prior.Multiple.Count | Should -Be 2
        }
        It 'timestamp-looking JSON strings remain exact strings in the journal' {
            $a=New-FixtureRecord;$a.Prior=@{Iso='2026-10-01T00:00:00Z';Legacy='/Date(0)/'}
            Write-RecoveryRecord $a;$r=Read-RecoveryRecords $OutDir;$r.Status | Should -Be 'Complete'
            $r.Items[0].Prior.Iso -is [string] | Should -BeTrue;$r.Items[0].Prior.Iso | Should -BeExactly $a.Prior.Iso
            $r.Items[0].Prior.Legacy -is [string] | Should -BeTrue;$r.Items[0].Prior.Legacy | Should -BeExactly $a.Prior.Legacy
        }
        It 'invalid schema <Fault> refuses before opening a publication stream' -ForEach @(
            @{Fault='extra field'},@{Fault='missing field'},@{Fault='version type'},@{Fault='resource type'},@{Fault='zero revision'},@{Fault='revision bound'},@{Fault='empty identity'},@{Fault='Intent observation'},@{Fault='Applied unobserved'},@{Fault='ownership'},@{Fault='state'},@{Fault='machine'},@{Fault='artifact shape'},@{Fault='artifact digest'},@{Fault='array bound'},@{Fault='map bound'},@{Fault='text bound'}
        ) {
            $a=New-FixtureRecord
            switch($Fault){
                'extra field'{$a.Extra=1} 'missing field'{$a.Remove('Limits')} 'zero revision'{$a.Revision=0} 'revision bound'{$a.Revision=1000001}
                'version type'{$a.SchemaVersion='1'} 'resource type'{$a.ResourceId=@('resource')}
                'empty identity'{$a.ResourceIdentity=@{}} 'Intent observation'{$a.AppliedObservation=@{Value='unverified'}} 'Applied unobserved'{$a.State='Applied'}
                ownership{$a.Ownership='Unknown'} state{$a.State='Unknown'} machine{$a.MachineId='22222222-2222-2222-2222-222222222222'}
                'artifact shape'{$a.Artifact.Extra=1} 'artifact digest'{$a.Artifact.Digest='wrong'}
                'array bound'{$a.Limits=[object[]](1..1025)} 'map bound'{$a.Prior=@{};foreach($i in 1..129){$a.Prior["k$i"]=$i}}
                'text bound'{$a.Prior.Value='x'*32769}
            }
            {Write-RecoveryRecord $a} | Should -Throw;Should -Invoke Open-RecoveryWrite -Times 0
        }
        It 'completed artifact must exist and match the checked digest before record publication' {
            $artifact=Join-Path $TestDrive 'artifact.bin';Write-FixtureText $artifact 'fixed artifact'
            Mock Get-NativeFileDigest {$safe=Assert-FixturePath $Path;(Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $safe -Algorithm SHA256).Hash.ToLowerInvariant()}
            $a=New-FixtureRecord;$a.Artifact=@{CanonicalPath=$artifact;Digest=(Get-NativeFileDigest $artifact);Complete=$true}
            Write-RecoveryRecord $a;(Read-RecoveryRecords $OutDir).Status | Should -Be 'Complete'
            Write-FixtureText $artifact 'changed artifact'
            (Read-RecoveryRecords $OutDir).Status | Should -Be 'Failed'
            $a.Revision=2;$a.State='Applied';$a.AppliedObservation=@{Value='checked'};{Write-RecoveryRecord $a} | Should -Throw
            Should -Invoke Publish-RecoveryFile -Times 1
        }
    }
}
