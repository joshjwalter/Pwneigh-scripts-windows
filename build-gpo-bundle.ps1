# build-gpo-bundle.ps1 - DEV BOX ONLY. Fills each box folder under prod\ with the GPOs its script applies.
# Reads the DISA STIG GPO package, copies only the GPOs we use, removes the competition-breaking lines, and writes
# CHANGES.md listing every line removed. Changes nothing on this machine: file copies plus LGPO /parse and /r /w only.
# Re-run it on each new quarterly DISA package instead of re-editing by hand.
#   .\build-gpo-bundle.ps1 -Package 'C:\Users\me\Downloads\U_STIG_GPO_Package_July_2026.zip' -Lgpo C:\path\LGPO.exe -AdminName <name>
# Output: prod\<box>\LGPO.exe + prod\<box>\GPO\OS\{GUID}\ (that box's OS baseline) + prod\<box>\GPO\Defender\{GUID}\.
# Only GPO\ and LGPO.exe are replaced; the box's script is left alone. CHANGES.md goes to -ChangesFile (dev box only: it
# names the new admin account).
# -AdminName: what the OS baselines rename the built-in Administrator to, instead of DISA's X_Admin (the first name a red
# teamer tries). Use the same name on every rebuild (it's in the last CHANGES.md) so it doesn't change under your team.
param(
    [Parameter(Mandatory)][string]$Package,
    [Parameter(Mandatory)][string]$Lgpo,
    [Parameter(Mandatory)][string]$AdminName,
    [string]$ProdDir = (Join-Path $PSScriptRoot '..\..\prod'),
    [string]$ChangesFile = (Join-Path $PSScriptRoot '..\..\gpo-bundle\CHANGES.md')
)
$ErrorActionPreference = 'Stop'

if ($AdminName.Length -gt 20 -or $AdminName -match '["/\\\[\]:;|=,+*?<>@\s]' -or $AdminName -in 'Administrator', 'Guest', 'X_Admin') {
    throw "-AdminName '$AdminName' is not usable: max 20 characters, no spaces or `" / \ [ ] : ; | = , + * ? < > @, and not Administrator/Guest/X_Admin"
}
$adminLine = "NewAdministratorName = `"$AdminName`""

# One folder per Windows box in the HPCC4 packet. Os is relative to the package root; the version suffix is wildcarded so
# the next quarterly package works unchanged. OS baselines are always the "Local Policies" copies (made for standalone
# boxes): the main-folder ones deny RDP to every local account and carry "ADD YOUR DOMAIN ADMINS" placeholders.
$Boxes = @(
    @{ Folder = 'manifest-2019'; Os = 'Support Files\Local Policies\DoD Windows Server 2019 MS v*\GPOs' },
    @{ Folder = 'assembly-2022'; Os = 'Support Files\Local Policies\DoD Windows Server 2022 MS v*\GPOs' }
)
$DefenderSrc = 'DoD Microsoft Defender Antivirus STIG v*\GPOs'   # copied unchanged into every box folder
# GptTmpl.inf lines removed from the OS baselines. Removing a line = "not configured": Windows keeps whatever the box has.
$InfRemovals = [ordered]@{
    '^NewGuestName\s*='                 = 'renames Guest to Visitor - pointless churn, Guest stays disabled anyway'
    '^MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy\\Enabled=' = 'FIPS-only crypto - can break older web apps, RDP/SSH clients, anything using MD5/RC4'
    '^SeImpersonatePrivilege\s*='        = 'replaces the impersonate list and can drop IIS_IUSRS - may break IIS app pools'
    '^LockoutDuration\s*='               = 'meaningless with lockout off (LockoutBadCount = 0)'
    '^ResetLockoutCount\s*='             = 'meaningless with lockout off (LockoutBadCount = 0)'
}
# GptTmpl.inf lines whose value is replaced.
$InfReplacements = [ordered]@{
    '^NewAdministratorName\s*=' = @{ Line = $adminLine; Why = "DISA's X_Admin is the first name a red teamer tries" }
    '^LockoutBadCount\s*='      = @{ Line = 'LockoutBadCount = 0'; Why = 'lockout off: red team knows plinktern/jmoney from the packet and could lock out the only admin and fail the RDP checks' }
}
# registry.pol keys removed from the OS baselines: the 2019 baseline carries firewall policy (outbound ALLOW on every
# profile + policy RDP rules) that would silently undo the script's own firewall. The firewall STIG is skipped for the same reason.
$PolKeyRemovals = @('^Software\\Policies\\Microsoft\\WindowsFirewall(\\|$)')

$short = Join-Path $env:TEMP 'gpob'   # LGPO can't open paths over 260 chars, and the package's paths get close
if (Test-Path $short) { Remove-Item $short -Recurse -Force }
New-Item -ItemType Directory -Path $short | Out-Null
$root = $Package
if ($Package -like '*.zip') { $root = Join-Path $short 'src'; Expand-Archive -Path $Package -DestinationPath $root }
if (-not (Test-Path $Lgpo)) { throw "LGPO.exe not found: $Lgpo" }
if ((Get-AuthenticodeSignature $Lgpo).SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw "LGPO.exe is not Microsoft-signed: $Lgpo" }

New-Item -ItemType Directory -Path $ProdDir -Force | Out-Null
$ProdDir = (Resolve-Path $ProdDir).Path
# Every GPO copy to make: the box's OS baseline (edited) and the Defender STIG (unchanged).
$Copies = foreach ($b in $Boxes) {
    $boxDir = Join-Path $ProdDir $b.Folder
    New-Item -ItemType Directory -Path $boxDir -Force | Out-Null
    if (Test-Path (Join-Path $boxDir 'GPO')) { Remove-Item (Join-Path $boxDir 'GPO') -Recurse -Force }
    Copy-Item $Lgpo (Join-Path $boxDir 'LGPO.exe') -Force
    @{ Label = "$($b.Folder) OS baseline"; Src = $b.Os; Dest = Join-Path $boxDir 'GPO\OS'; Edit = $true }
    @{ Label = "$($b.Folder) Defender"; Src = $DefenderSrc; Dest = Join-Path $boxDir 'GPO\Defender'; Edit = $false }
}

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

$changes = @("# GPO bundle changes", '', "Built $(Get-Date -Format 'yyyy-MM-dd HH:mm') from ``$(Split-Path $Package -Leaf)`` by build-gpo-bundle.ps1 into ``$ProdDir``.",
    'Everything not listed here is exactly as DISA shipped it.', '',
    "**Built-in Administrator is renamed to ``$AdminName``.** Rebuild with ``-AdminName $AdminName`` to keep that name.", '')
foreach ($c in $Copies) {
    $src = @(Resolve-Path (Join-Path $root $c.Src) -ErrorAction SilentlyContinue)
    if ($src.Count -ne 1) { throw "expected exactly one match for '$($c.Src)', found $($src.Count)" }
    New-Item -ItemType Directory -Path (Split-Path $c.Dest) -Force | Out-Null
    Copy-Item $src[0].Path $c.Dest -Recurse
    Remove-Item (Join-Path $c.Dest 'manifest.xml') -ErrorAction SilentlyContinue
    $changes += "## $($c.Label)  (from ``$($src[0].Path.Substring($root.Length + 1))``)", ''
    foreach ($b in Get-ChildItem $c.Dest -Directory) {
        $name = if ((Get-Content (Join-Path $b.FullName 'Backup.xml') -Raw) -match '<DisplayName><!\[CDATA\[([^\]]*)') { $Matches[1] } else { $b.Name }
        $changes += "### $name ``$($b.Name)``"
        if (-not $c.Edit) { $changes += '- unchanged', ''; continue }
        Remove-Item (Join-Path $b.FullName 'gpreport.xml') -ErrorAction SilentlyContinue   # would still show the removed settings
        foreach ($inf in Get-ChildItem $b.FullName -Recurse -Filter GptTmpl.inf) {
            $lines = [IO.File]::ReadAllLines($inf.FullName)   # UTF-16 LE with BOM; read and written back the same way
            $changed = $false
            $new = foreach ($l in $lines) {
                $rm = @($InfRemovals.Keys | Where-Object { $l -match $_ })
                $rp = @($InfReplacements.Keys | Where-Object { $l -match $_ })
                if ($rm.Count) { $changes += "- GptTmpl.inf: removed ``$l`` - $($InfRemovals[$rm[0]])"; $changed = $true }
                elseif ($rp.Count) { $r = $InfReplacements[$rp[0]]; $changes += "- GptTmpl.inf: ``$l`` -> ``$($r.Line)`` - $($r.Why)"; $changed = $true; $r.Line }
                else { $l }
            }
            if ($changed) { [IO.File]::WriteAllLines($inf.FullName, [string[]]$new, [Text.Encoding]::Unicode) }
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

# Verify: every registry.pol still parses and has no firewall policy left; every GptTmpl.inf kept its BOM and sections;
# every box's OS baseline has the new admin name and lockout off.
foreach ($c in $Copies) {
    foreach ($pol in Get-ChildItem $c.Dest -Recurse -Filter registry.pol) {
        $p = if ($pol.FullName -match '\\User\\') { '/u' } else { '/m' }
        $tmp = Join-Path $short 'v.pol'; Copy-Item $pol.FullName $tmp -Force
        $keys = @(Split-PolBlocks (Invoke-Lgpo '/parse', '/q', $p, $tmp) | ForEach-Object { $_[1] })
        if (@($keys | Where-Object { $k = $_; @($PolKeyRemovals | Where-Object { $k -match $_ }).Count }).Count) { throw "firewall policy still in $($pol.FullName)" }
        Write-Host "OK  $($pol.FullName.Substring($ProdDir.Length + 1))  ($($keys.Count) values)"
    }
    foreach ($inf in Get-ChildItem $c.Dest -Recurse -Filter GptTmpl.inf) {
        $bytes = [IO.File]::ReadAllBytes($inf.FullName); $lines = [IO.File]::ReadAllLines($inf.FullName)
        if ($bytes[0] -ne 0xFF -or $bytes[1] -ne 0xFE) { throw "lost its UTF-16 BOM: $($inf.FullName)" }
        if (-not ($lines -contains '[Version]')) { throw "no [Version] section: $($inf.FullName)" }
        if ($c.Edit -and -not ($lines -contains $adminLine -and $lines -contains 'LockoutBadCount = 0')) { throw "$($c.Label) is missing $adminLine or LockoutBadCount = 0" }
        Write-Host "OK  $($inf.FullName.Substring($ProdDir.Length + 1))  ($(@($lines | Where-Object { $_ -match '=' }).Count) lines)"
    }
}
New-Item -ItemType Directory -Path (Split-Path $ChangesFile) -Force | Out-Null
Set-Content $ChangesFile $changes -Encoding UTF8
Remove-Item $short -Recurse -Force
Write-Host "Built: $(($Boxes | ForEach-Object { Join-Path $ProdDir $_.Folder }) -join ', ')  (see $ChangesFile - it stays on this box)."
Write-Host "Built-in Administrator will be renamed to: $AdminName  - tell your team." -ForegroundColor Yellow
