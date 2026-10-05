# Fixture IO authorization is independent of production tunables/helpers.
function Assert-FixturePath {
    param([string]$Path)
    if(-not $TestDrive -or $TestDrive -notmatch '^[A-Za-z]:[\\/]' -or -not $Path -or $Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2) -match '[\x00-\x1f*?:~]'){throw 'Fixture literal absolute path required'}
    $root=[IO.Path]::GetFullPath($TestDrive).TrimEnd('\')
    $drive=Microsoft.PowerShell.Management\Get-PSDrive -Name TestDrive -ErrorAction Stop
    if($drive.Provider.Name -ne 'FileSystem' -or $drive.Root -notmatch '^[A-Za-z]:[\\/]' -or [IO.Path]::GetFullPath($drive.Root).TrimEnd('\') -cne $root){throw 'Fixture root differs from authoritative TestDrive'}
    $full=[IO.Path]::GetFullPath($Path)
    if(-not $full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Outside disposable TestDrive'}
    foreach($part in $Path.Substring(3).Replace('/','\').Split('\')){
        if(-not $part -or $part.EndsWith('.') -or $part.EndsWith(' ') -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)'){throw 'Unsupported fixture component'}
    }
    $cursor=$full
    while($cursor){
        try {if(([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Fixture reparse component refused'}}
        catch [IO.FileNotFoundException] {} catch [IO.DirectoryNotFoundException] {}
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
    $full
}
function New-FixtureDirectory {param([string]$Path);$safe=Assert-FixturePath $Path;$null=[IO.Directory]::CreateDirectory($safe)}
function Write-FixtureText {param([string]$Path,[string]$Text);$safe=Assert-FixturePath $Path;[IO.File]::WriteAllText($safe,$Text)}
function Read-FixtureText {param([string]$Path);$safe=Assert-FixturePath $Path;[IO.File]::ReadAllText($safe)}
function Open-FixtureStream {param([string]$Path,[IO.FileMode]$Mode);$safe=Assert-FixturePath $Path;[IO.File]::Open($safe,$Mode,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
function Publish-FixtureFile {param([string]$Temporary,[string]$Committed);$temp=Assert-FixturePath $Temporary;$target=Assert-FixturePath $Committed;if([IO.File]::Exists($target)){[IO.File]::Replace($temp,$target,[System.Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($temp,$target)}}
function Assert-DefinitionSource {
    param([string]$Path)
    $expectedPath=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\hpcc4-simple.ps1'))
    if([IO.Path]::GetFullPath($Path) -cne $expectedPath){throw 'Unknown source input'}
    # Refresh only after reviewing the changed source and selected test graph.
    $expectedDigest='F3C2B689430BE957363FA8A07CF6477DFF2A2968CC93E69CC8BAB2098E57D85F'
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$actual=-join($sha.ComputeHash([IO.File]::ReadAllBytes($expectedPath)) | ForEach-Object {$_.ToString('x2')})} finally {$sha.Dispose()}
    if($actual -ine $expectedDigest){throw 'Source differs from audited fingerprint'}
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if($errors.Count -or $ast.EndBlock.Statements[-1].Extent.Text -ne 'if ($MyInvocation.InvocationName -ne ''.'') { Invoke-DirectEntry }'){throw 'Unaudited source entry guard'}
    foreach($statement in $ast.EndBlock.Statements | Select-Object -SkipLast 1){
        if($statement -is [Management.Automation.Language.FunctionDefinitionAst]){continue}
        if($statement -isnot [Management.Automation.Language.AssignmentStatementAst]){throw 'Unaudited load statement'}
        $commands=@($statement.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true))
        if($commands.Count -and ($commands.Count -ne 1 -or $commands[0].GetCommandName() -ne 'New-RunState' -or $statement.Left.Extent.Text -ne '$null')){throw 'Unaudited load command'}
        if(@($statement.FindAll({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst]},$true)).Count){throw 'Unaudited load CLR invocation'}
    }
}
function Set-FixtureBytes {param($Stream,[byte[]]$Bytes);if($Stream -isnot [IO.FileStream]){throw 'Fixture FileStream required'};$null=Assert-FixturePath $Stream.Name;$Stream.Write($Bytes,0,$Bytes.Length)}
function Flush-FixtureStream {param($Stream);if($Stream -isnot [IO.FileStream]){throw 'Fixture FileStream required'};$null=Assert-FixturePath $Stream.Name;$Stream.Flush($true)}
function Close-FixtureStream {param($Stream);if($Stream -isnot [IO.FileStream]){throw 'Fixture FileStream required'};$null=Assert-FixturePath $Stream.Name;$Stream.Dispose()}
function ConvertTo-FixtureItem {param($Item);$Item | Add-Member NoteProperty PSProvider ([pscustomobject]@{Name='FileSystem'}) -Force;$Item | Add-Member NoteProperty PSIsContainer ($Item -is [IO.DirectoryInfo]) -Force;$Item}
function Get-FixtureEntries {param([string]$Path,[string]$Filter='*');$safe=Assert-FixturePath $Path;foreach($item in ([IO.DirectoryInfo]::new($safe)).GetFileSystemInfos($Filter)){$null=Assert-FixturePath $item.FullName;ConvertTo-FixtureItem $item}}
function Get-FixtureItem {param([string]$Path);$full=[IO.Path]::GetFullPath($Path);$root=[IO.Path]::GetFullPath($TestDrive).TrimEnd('\');if($full.TrimEnd('\') -ceq $root){$null=Assert-FixturePath (Join-Path $root 'fixed-root-validation-leaf');$safe=$root}else{$safe=Assert-FixturePath $Path};$item=if([IO.Directory]::Exists($safe)){[IO.DirectoryInfo]::new($safe)}else{[IO.FileInfo]::new($safe)};if(-not $item.Exists){throw 'Fixture item missing'};ConvertTo-FixtureItem $item}
function Get-FixtureContent {param([string]$Path,[switch]$Raw);$safe=Assert-FixturePath $Path;$text=[IO.File]::ReadAllText($safe);if($Raw){$text}else{$text -split '\r?\n'}}
function Remove-FixtureFile {param([string]$Path);$safe=Assert-FixturePath $Path;if([IO.Directory]::Exists($safe)){throw 'Fixture file deletion only'};[IO.File]::Delete($safe)}
function Test-FixtureExists {
    param([string]$Path)
    $root=[IO.Path]::GetFullPath($TestDrive).TrimEnd('\');$full=[IO.Path]::GetFullPath($Path)
    # Bootstrap ancestor existence is synthetic; no actual host ancestor read is opted in.
    if($root.Equals($full,[StringComparison]::OrdinalIgnoreCase) -or $root.StartsWith($full.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){
        $null=Assert-FixturePath (Join-Path $root 'fixed-root-validation-leaf');return $true
    }
    $safe=Assert-FixturePath $Path
    [bool]([IO.File]::Exists($safe) -or [IO.Directory]::Exists($safe))
}
function Resolve-FixtureOrSourcePath {
    param([string]$Path)
    $full=[IO.Path]::GetFullPath($Path)
    if($full -notin @([IO.Path]::GetFullPath($PSScriptRoot),[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent)))){$full=Assert-FixturePath $Path}
    Microsoft.PowerShell.Management\Resolve-Path -LiteralPath $full -ErrorAction Stop
}
function Assert-ResetDefinitionSource {
    param([string]$Path)
    $expected=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\reset-hpcc4.ps1'))
    if([IO.Path]::GetFullPath($Path) -cne $expected){throw 'Unknown reset source'}
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$actual=-join($sha.ComputeHash([IO.File]::ReadAllBytes($expected)) | ForEach-Object {$_.ToString('x2')})}finally{$sha.Dispose()}
    if($actual -ine '60034B109D1F0E7EBB25A2B70255081352C305F2450D98DCD048D0F3FE3A3EBA'){throw 'Reset differs from audited fingerprint'}
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($expected,[ref]$tokens,[ref]$errors)
    if($errors.Count -or $ast.EndBlock.Statements.Count -ne 2 -or $ast.EndBlock.Statements[0] -isnot [Management.Automation.Language.FunctionDefinitionAst] -or $ast.EndBlock.Statements[0].Name -ne 'Invoke-Hpcc4Reset' -or $ast.EndBlock.Statements[1].Extent.Text -ne 'if ($MyInvocation.InvocationName -ne ''.'') { exit (Invoke-Hpcc4Reset $MainScript) }'){throw 'Unaudited reset entry structure'}
}
