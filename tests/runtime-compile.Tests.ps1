# Separate compiler-only selection. Never invokes a bridge method or loads production definitions.
Describe 'B audited bridge compilation only' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'FixtureSafety.ps1')
        $script:compileSource=Join-Path $PSScriptRoot '..\hpcc4-simple.ps1'
        Assert-DefinitionSource $compileSource
        $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($compileSource,[ref]$tokens,[ref]$errors)
        $functions=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq 'Initialize-ObjectIdentityApi'})
        if($errors.Count -or $functions.Count -ne 1){throw 'Bridge definition is ambiguous'}
        $commands=@($functions[0].Body.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-Type'},$true))
        if($commands.Count -ne 1 -or $commands[0].CommandElements.Count -ne 5 -or $commands[0].CommandElements[1].Extent.Text -ne '-TypeDefinition' -or $commands[0].CommandElements[2] -isnot [Management.Automation.Language.StringConstantExpressionAst] -or $commands[0].CommandElements[2].StringConstantType.ToString() -ne 'SingleQuotedHereString'){throw 'Bridge payload must be one nonexpandable audited literal'}
        $script:bridgeLiteral=$commands[0].CommandElements[2].Value
        if($bridgeLiteral -match 'static\s+Hpcc4ObjectIdentity\s*\('){throw 'Executable static initializer refused'}
        $removal=@($ast.EndBlock.Statements | Where-Object Name -eq 'Start-DeferredScriptRemoval')[0]
        $body=@($removal.FindAll({param($n)$n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.StringConstantType.ToString() -eq 'SingleQuotedHereString'},$true))[0].Value
        $childAst=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
        $childCommand=@($childAst.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-Type'},$true))[0]
        $literal=$childCommand.CommandElements[2]
        $inertLiteral=($literal -is [Management.Automation.Language.StringConstantExpressionAst] -and $literal.StringConstantType.ToString() -eq 'DoubleQuotedHereString') -or
            ($literal -is [Management.Automation.Language.ExpandableStringExpressionAst] -and -not $literal.NestedExpressions.Count)
        if($errors.Count -or -not $inertLiteral -or $literal.Value -match 'static\s+ExactFileRemoval\s*\('){throw 'Unaudited deferred compiler literal'}
        # Both actual production literals are compiled, with using declarations
        # moved to the file head. No bridge/removal method is invoked.
        $script:bridgeLiteral="using System.IO;`nusing System.Security.Cryptography;`n"+$bridgeLiteral+"`n"+($literal.Value -replace '(?m)^using [^;]+;\r?\n','')
    }
    It 'compiles the exact frozen bridge with compiler files confined to TestDrive' {
        if(-not [Environment]::Is64BitProcess -or ('Hpcc4ObjectIdentity' -as [type])){throw 'Fresh dedicated x64 compiler process required'}
        $compilerRoot=Join-Path $TestDrive 'compiler';New-FixtureDirectory $compilerRoot
        $safeRoot=Assert-FixturePath $compilerRoot;$output=Assert-FixturePath (Join-Path $safeRoot 'bridge.dll')
        $priorTemp=[Environment]::GetEnvironmentVariable('TEMP','Process');$priorTmp=[Environment]::GetEnvironmentVariable('TMP','Process')
        try {
            [Environment]::SetEnvironmentVariable('TEMP',$safeRoot,'Process');[Environment]::SetEnvironmentVariable('TMP',$safeRoot,'Process')
            if($PSVersionTable.PSEdition -eq 'Desktop'){
                $runtime=[Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
                $compiler=Join-Path $runtime 'csc.exe'
                if(-not [IO.Path]::IsPathRooted($runtime) -or $runtime -notmatch '\\Microsoft\.NET\\Framework64\\v4\.0\.30319\\$' -or -not [IO.File]::Exists($compiler)){throw 'Unexpected framework compiler provenance'}
                $provider=New-Object Microsoft.CSharp.CSharpCodeProvider
                try {
                    $parameters=New-Object CodeDom.Compiler.CompilerParameters
                    $parameters.GenerateExecutable=$false;$parameters.GenerateInMemory=$true;$parameters.OutputAssembly=$output
                    $parameters.TempFiles=[CodeDom.Compiler.TempFileCollection]::new($safeRoot,$true)
                    $reference=Join-Path $runtime 'System.dll'
                    if(-not [IO.File]::Exists($reference)){throw 'Framework reference unavailable'}
                    $null=$parameters.ReferencedAssemblies.Add($reference)
                    $result=$provider.CompileAssemblyFromSource($parameters,[string[]]@($bridgeLiteral))
                    @($result.Errors | Where-Object {-not $_.IsWarning}).Count | Should -Be 0
                    $result.NativeCompilerReturnValue | Should -Be 0
                    foreach($file in $parameters.TempFiles){$null=Assert-FixturePath $file}
                    $type=$result.CompiledAssembly.GetType('Hpcc4ObjectIdentity',$true)
                    Write-Host "Compiler-only provenance: $compiler"
                } finally {$provider.Dispose()}
            }else{
                # Output is explicit; Core Add-Type uses the bundled Roslyn compiler in this process.
                # PassThru loads/locks the output DLL on Windows, preventing
                # Pester's fixture cleanup. Reflect an in-memory byte load instead.
                Add-Type -TypeDefinition $bridgeLiteral -OutputAssembly $output -ErrorAction Stop
                $null=Assert-FixturePath $output
                $assembly=[Reflection.Assembly]::Load([IO.File]::ReadAllBytes($output))
                $type=$assembly.GetType('Hpcc4ObjectIdentity',$true)
                Write-Host "Compiler-only provenance: $PSHOME (Core Add-Type)"
            }
            (Test-FixtureExists $output) | Should -BeTrue
            (Get-FixtureItem $output).Length | Should -BeGreaterThan 0
            $type | Should -Not -BeNullOrEmpty
            $type.GetMethod('CreateProtectedDirectory').IsStatic | Should -BeTrue
            $type.GetMethod('Read').IsStatic | Should -BeTrue
            $type.Assembly.GetType('ExactFileRemoval',$true).GetMethod('Delete').IsStatic | Should -BeTrue
            $security=$type.GetNestedType('SecurityAttributes')
            [Runtime.InteropServices.Marshal]::SizeOf([Activator]::CreateInstance($security)) | Should -Be 24
            foreach($entry in Get-FixtureEntries $safeRoot){$null=Assert-FixturePath $entry.FullName}
        } finally {[Environment]::SetEnvironmentVariable('TEMP',$priorTemp,'Process');[Environment]::SetEnvironmentVariable('TMP',$priorTmp,'Process')}
    }
}
