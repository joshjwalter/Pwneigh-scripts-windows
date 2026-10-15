# Switch MariaDB to a no-permission service account (manifest-4)

Goal: MariaDB runs as `NT SERVICE\<name>`, a Windows virtual account with no
password, no admin rights, and access only to the folders you grant it.

- When: after hpcc4-manifest.ps1 finishes. If MariaDB ran as Administrator, the
  script changed and renamed that account, so MariaDB won't come back after its
  next restart until you do this.
- Downtime: MariaDB is down for about 10-30 seconds, from Stop to Start.
- Shell: elevated PowerShell. Paste each block in order.

## 1. Find the service (installs may be weird)

```powershell
Get-CimInstance Win32_Service | Where-Object { "$($_.Name) $($_.DisplayName) $($_.PathName)" -match 'maria|mysql' } |
    Format-List Name, DisplayName, State, StartName, PathName
# What is actually listening on 3306, in case it's not the service you expected:
Get-NetTCPConnection -LocalPort 3306 -State Listen | ForEach-Object { Get-Process -Id $_.OwningProcess | Select-Object Id, Path }
```

- Use the **Name** field, not DisplayName (often `MariaDB`, sometimes `MySQL`
  or `MySQL80`).
- StartName already `NT SERVICE\...`, `NT AUTHORITY\LocalService` or
  `NT AUTHORITY\NetworkService`: it already runs with low rights. **Stop here.**
- Nothing listed, but 3306 is listening: MariaDB isn't a service. It was started
  some other way (scheduled task, startup folder, XAMPP). Leave it alone and
  note it in your persistence review.

```powershell
$svc  = 'MariaDB'                  # <-- the Name from above
$acct = "NT SERVICE\$svc"
$s    = Get-CimInstance Win32_Service -Filter "Name='$svc'"
"$svc was running as: $($s.StartName)" | Tee-Object -FilePath "C:\HPCC4\$svc-account-before.txt"
$s.PathName
```

## 2. Find every folder it uses

The PathName usually holds `--defaults-file=...\my.ini`. If there's no
`--defaults-file`, look for `my.ini` (or `my.cnf`) in the install's `data\`
folder or in the folder one level above `bin\`.

```powershell
$ini = 'C:\Program Files\MariaDB 11.4\data\my.ini'    # <-- from PathName
Select-String -Path $ini -Pattern '^\s*(datadir|basedir|tmpdir|log[-_]error|general[-_]log[-_]file|slow[-_]query[-_]log[-_]file|log[-_]bin|secure[-_]file[-_]priv|socket)\s*='
```

Write down:
- **datadir**: needs Modify. If it isn't in my.ini, it's the folder that
  holds my.ini.
- **Install folder** (the one containing `bin\mysqld.exe`): needs Read.
- **Any log, tmp or secure-file folder** outside datadir: needs Modify.

## 3. Stop, grant, switch, start

```powershell
$data    = 'C:\Program Files\MariaDB 11.4\data'       # <-- datadir
$install = 'C:\Program Files\MariaDB 11.4'            # <-- folder with bin\
$extra   = @()                                        # <-- other log/tmp folders, if any

Stop-Service $svc -Force
icacls $install /grant "${acct}:(OI)(CI)RX" /T /C /Q
foreach ($d in @($data) + $extra) { icacls $d /grant "${acct}:(OI)(CI)M" /T /C /Q }
(Invoke-CimMethod -InputObject $s -MethodName Change -Arguments @{ StartName = $acct; StartPassword = '' }).ReturnValue   # 0 = OK
Start-Service $svc
```

If `Change` returns something other than 0, use the GUI instead. Run
`services.msc`, open the service's Properties, go to the **Log On** tab and pick
**This account**. Type `NT SERVICE\MariaDB` (with your service name), clear both
password boxes, click OK, then Start.

## 4. Check it works

```powershell
(Get-CimInstance Win32_Service -Filter "Name='$svc'") | Select-Object Name, State, StartName
Get-NetTCPConnection -LocalPort 3306 -State Listen
& "$install\bin\mysql.exe" -u root -p -e "SELECT 1"    # or the scored DB user
```

The check passes when State is Running, StartName is `NT SERVICE\...`, 3306 is
listening and the query returns. Then confirm the scoreboard shows MariaDB up,
and ask whoever watches assembly to check that the Jenkins backup job still runs.

**Won't start?** Read the end of the error log. It names the file or folder it
couldn't open. Grant Modify on that path and Start again.

```powershell
Get-ChildItem $data -Filter *.err | Sort-Object LastWriteTime | Select-Object -Last 1 | Get-Content -Tail 30
```

## 5. Roll back (if it still won't start within a few minutes)

```powershell
$s = Get-CimInstance Win32_Service -Filter "Name='$svc'"
Invoke-CimMethod -InputObject $s -MethodName Change -Arguments @{ StartName = 'LocalSystem'; StartPassword = '' }
Start-Service $svc
```

If it ran as a real user before (see `C:\HPCC4\<name>-account-before.txt`), put
that account back in the Log On tab instead. Use the account's current name and
the new password: the built-in Administrator is now `Salty_Goose47`.
