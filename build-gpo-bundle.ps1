# build-gpo-bundle.ps1 - DEV BOX ONLY. Builds the competition GPO bundle that hpcc4-simple.ps1's Install-DodGpo applies.
# Reads the DISA STIG GPO package, copies only the GPOs we use, removes the competition-breaking lines, and writes
# CHANGES.md listing every line removed. Changes nothing on this machine: file copies plus LGPO /parse and /r /w only.
# Re-run it on each new quarterly DISA package instead of re-editing by hand.
#   .\build-gpo-bundle.ps1 -Package 'C:\Users\me\Downloads\U_STIG_GPO_Package_July_2026.zip' -Lgpo C:\path\LGPO.exe -AdminName <name>
# Output (-OutDir): CHANGES.md (dev box only - it names the new admin account) and zip\, holding LGPO.exe +
# GPO\<Server2012R2|Server2022|Server2025|Defender>\{GUID}\... Merge the CONTENTS of zip\ into the ROOT of your tools zip,
# so on the box they land at $ToolsDir\LGPO.exe and $ToolsDir\GPO\.
# -AdminName: what the OS baselines rename the built-in Administrator to, instead of DISA's X_Admin (the first name a red
# teamer tries). Use the same name on every rebuild (it's in the last CHANGES.md) so it doesn't change under your team.
param(
    [Parameter(Mandatory)][string]$Package,
    [Parameter(Mandatory)][string]$Lgpo,
    [Parameter(Mandatory)][string]$AdminName,
    [string]$OutDir = (Join-Path $PSScriptRoot '..\..\gpo-bundle')
)
$ErrorActionPreference = 'Stop'

if ($AdminName.Length -gt 20 -or $AdminName -match '["/\\\[\]:;|=,+*?<>@\s]' -or $AdminName -in 'Administrator', 'Guest', 'X_Admin') {
    throw "-AdminName '$AdminName' is not usable: max 20 characters, no spaces or `" / \ [ ] : ; | = , + * ? < > @, and not Administrator/Guest/X_Admin"
}
$adminLine = "NewAdministratorName = `"$AdminName`""

# Which GPO backups go in the bundle. Src is relative to the package root; the version suffix is wildcarded so the next
# quarterly package works unchanged. OS baselines are always the "Local Policies" copies (made for standalone boxes):
# the main-folder ones deny RDP to every local account and carry "ADD YOUR DOMAIN ADMINS" placeholders.
$Sources = @(
    @{ Folder = 'Server2012R2'; Src = 'Support Files\Local Policies\DoD Windows Server 2012 R2 MS v*\GPOs'; Edit = $true },
    @{ Folder = 'Server2022';   Src = 'Support Files\Local Policies\DoD Windows Server 2022 MS v*\GPOs';    Edit = $true },
    @{ Folder = 'Server2025';   Src = 'Support Files\Local Policies\DoD Windows Server 2025 MS v*\GPOs';    Edit = $true },
    @{ Folder = 'Defender';     Src = 'DoD Microsoft Defender Antivirus STIG v*\GPOs';                      Edit = $false }
)
# GptTmpl.inf lines removed from the OS baselines. Removing a line = "not configured": Windows keeps whatever the box has.
# (NewAdministratorName is not removed: its value is replaced with -AdminName.)
$InfRemovals = [ordered]@{
    '^NewGuestName\s*='                 = 'renames Guest to Visitor - pointless churn, Guest stays disabled anyway'
    '^MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy\\Enabled=' = 'FIPS-only crypto - can break older web apps, RDP/SSH clients, anything using MD5/RC4'
    '^SeImpersonatePrivilege\s*='        = 'replaces the impersonate list and can drop IIS_IUSRS - may break IIS app pools (revisit once the packet says whether IIS is scored)'
    '^SeRemoteInteractiveLogonRight\s*=' = '2012 R2 only: RDP for Administrators only, dropping Remote Desktop Users - 2022/2025 baselines leave this at the Windows default'
}
# registry.pol keys removed from the OS baselines: 2012 R2's baseline carries firewall policy (outbound ALLOW on every
# profile + policy RDP rules) that would silently undo the script's own firewall. The firewall STIG is skipped for the same reason.
$PolKeyRemovals = @('^Software\\Policies\\Microsoft\\WindowsFirewall(\\|$)')

$short = Join-Path $env:TEMP 'gpob'   # LGPO can't open paths over 260 chars, and the package's paths get close
if (Test-Path $short) { Remove-Item $short -Recurse -Force }
New-Item -ItemType Directory -Path $short | Out-Null
$root = $Package
if ($Package -like '*.zip') { $root = Join-Path $short 'src'; Expand-Archive -Path $Package -DestinationPath $root }
if (-not (Test-Path $Lgpo)) { throw "LGPO.exe not found: $Lgpo" }
if ((Get-AuthenticodeSignature $Lgpo).SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw "LGPO.exe is not Microsoft-signed: $Lgpo" }

if (Test-Path $OutDir) { Remove-Item $OutDir -Recurse -Force }
$gpoOut = Join-Path $OutDir 'zip\GPO'
New-Item -ItemType Directory -Path $gpoOut -Force | Out-Null
Copy-Item $Lgpo (Join-Path $OutDir 'zip\LGPO.exe')
$OutDir = (Resolve-Path $OutDir).Path

# Runs LGPO on a short-path copy. /parse writes LGPO text to stdout; /r /w builds a registry.pol from LGPO text.
# LGPO prints its banner to stderr, which PowerShell 5.1 turns into a terminating error under 'Stop': the exit code decides instead.
function Invoke-Lgpo {
    param([string[]]$LgpoArgs)
    $ErrorActionPreference = 'Continue'; $out = & $Lgpo @LgpoArgs 2>$null
    if ($LASTEXITCODE) { throw "LGPO $($LgpoArgs -join ' ') failed: exit $LASTEXITCODE" }; $out
}
function Get-PolText { param([string]$Pol) $tmp = Join-Path $short 'p.pol'; Copy-Item $Pol $tmp -Force; Invoke-Lgpo '/parse', '/q', '/m', $tmp }
# LGPO text is blocks of: Computer / key / value / TYPE:data, separated by blank lines. Returns each block as one string array.
function Split-PolBlocks {
    param([string[]]$Text)
    $cur = @(); foreach ($l in $Text) { if ($l -match '^\s*(;|$)') { if ($cur) { , $cur }; $cur = @() } else { $cur += $l } }
    if ($cur) { , $cur }
}

$changes = @("# GPO bundle changes", '', "Built $(Get-Date -Format 'yyyy-MM-dd HH:mm') from ``$(Split-Path $Package -Leaf)`` by build-gpo-bundle.ps1.",
    'Everything not listed here is exactly as DISA shipped it. Lockout (3 bad attempts / 15 min) is deliberately kept.', '',
    "**Built-in Administrator is renamed to ``$AdminName``.** Rebuild with ``-AdminName $AdminName`` to keep that name.", '')
foreach ($s in $Sources) {
    $src = @(Resolve-Path (Join-Path $root $s.Src) -ErrorAction SilentlyContinue)
    if ($src.Count -ne 1) { throw "expected exactly one match for '$($s.Src)', found $($src.Count)" }
    $dest = Join-Path $gpoOut $s.Folder
    Copy-Item $src[0].Path $dest -Recurse
    Remove-Item (Join-Path $dest 'manifest.xml') -ErrorAction SilentlyContinue
    $changes += "## $($s.Folder)  (from ``$($src[0].Path.Substring($root.Length + 1))``)", ''
    foreach ($b in Get-ChildItem $dest -Directory) {
        $name = if ((Get-Content (Join-Path $b.FullName 'Backup.xml') -Raw) -match '<DisplayName><!\[CDATA\[([^\]]*)') { $Matches[1] } else { $b.Name }
        $changes += "### $name ``$($b.Name)``"
        if (-not $s.Edit) { $changes += '- unchanged', ''; continue }
        Remove-Item (Join-Path $b.FullName 'gpreport.xml') -ErrorAction SilentlyContinue   # would still show the removed settings
        foreach ($inf in Get-ChildItem $b.FullName -Recurse -Filter GptTmpl.inf) {
            $lines = [IO.File]::ReadAllLines($inf.FullName)   # UTF-16 LE with BOM; read and written back the same way
            $drop = @($lines | Where-Object { $l = $_; @($InfRemovals.Keys | Where-Object { $l -match $_ }).Count })
            foreach ($d in $drop) { $why = $InfRemovals[@($InfRemovals.Keys | Where-Object { $d -match $_ })[0]]; $changes += "- GptTmpl.inf: removed ``$d`` - $why" }
            $rename = @($lines | Where-Object { $_ -match '^NewAdministratorName\s*=' })
            foreach ($r in $rename) { $changes += "- GptTmpl.inf: ``$r`` -> ``$adminLine`` - DISA's X_Admin is the first name a red teamer tries" }
            if ($drop.Count -or $rename.Count) {
                $new = @($lines | Where-Object { $drop -notcontains $_ } | ForEach-Object { if ($_ -match '^NewAdministratorName\s*=') { $adminLine } else { $_ } })
                [IO.File]::WriteAllLines($inf.FullName, $new, [Text.Encoding]::Unicode)
            }
        }
        foreach ($pol in Get-ChildItem $b.FullName -Recurse -Filter registry.pol | Where-Object { $_.FullName -match '\\Machine\\' }) {
            $blocks = @(Split-PolBlocks (Get-PolText $pol.FullName))
            $drop = @($blocks | Where-Object { $k = $_[1]; @($PolKeyRemovals | Where-Object { $k -match $_ }).Count })
            if (-not $drop.Count) { continue }
            $keep = @($blocks | Where-Object { $k = $_[1]; -not @($PolKeyRemovals | Where-Object { $k -match $_ }).Count })
            $txt = Join-Path $short 'keep.txt'; $new = Join-Path $short 'new.pol'
            Set-Content $txt (($keep | ForEach-Object { ($_ -join "`r`n") + "`r`n" }) -join "`r`n") -Encoding Unicode
            $null = Invoke-Lgpo '/r', $txt, '/w', $new
            Copy-Item $new $pol.FullName -Force
            $changes += "- registry.pol: removed $($drop.Count) firewall policy values (``$($drop[0][1])`` and below) - outbound ALLOW on every profile + policy RDP rules would undo the script's firewall"
        }
        $changes += ''
    }
}

# Verify: every registry.pol still parses; every GptTmpl.inf kept its BOM and sections; every OS baseline has the new admin name.
foreach ($pol in Get-ChildItem $gpoOut -Recurse -Filter registry.pol) {
    $p = if ($pol.FullName -match '\\User\\') { '/u' } else { '/m' }
    $tmp = Join-Path $short 'v.pol'; Copy-Item $pol.FullName $tmp -Force
    $keys = @(Split-PolBlocks (Invoke-Lgpo '/parse', '/q', $p, $tmp) | ForEach-Object { $_[1] })
    Write-Host "OK  $($pol.FullName.Substring($OutDir.Length + 1))  ($($keys.Count) values)"
}
foreach ($inf in Get-ChildItem $gpoOut -Recurse -Filter GptTmpl.inf) {
    $bytes = [IO.File]::ReadAllBytes($inf.FullName); $lines = [IO.File]::ReadAllLines($inf.FullName)
    if ($bytes[0] -ne 0xFF -or $bytes[1] -ne 0xFE) { throw "lost its UTF-16 BOM: $($inf.FullName)" }
    if (-not ($lines -contains '[Version]')) { throw "no [Version] section: $($inf.FullName)" }
    Write-Host "OK  $($inf.FullName.Substring($OutDir.Length + 1))  ($(@($lines | Where-Object { $_ -match '=' }).Count) lines)"
}
$renamed = @(Get-ChildItem $gpoOut -Recurse -Filter GptTmpl.inf | Where-Object { [IO.File]::ReadAllLines($_.FullName) -contains $adminLine })
foreach ($f in 'Server2012R2', 'Server2022', 'Server2025') { if (-not @($renamed | Where-Object { $_.FullName -match "\\$f\\" }).Count) { throw "$f baseline has no $adminLine" } }
Set-Content (Join-Path $OutDir 'CHANGES.md') $changes -Encoding UTF8
Remove-Item $short -Recurse -Force
Write-Host "Bundle built: $OutDir  (see CHANGES.md). Merge the CONTENTS of zip\ into the ROOT of your tools zip; CHANGES.md stays on this box."
Write-Host "Built-in Administrator will be renamed to: $AdminName  - tell your team." -ForegroundColor Yellow
