# Switch Jenkins to a no-permission service account (assembly-4)

Goal: Jenkins runs as `NT SERVICE\<name>`, a Windows virtual account with no
password, no admin rights, and access only to the folders you grant it.

- When: after hpcc4-assembly.ps1 finishes. If Jenkins ran as Administrator, the
  script changed and renamed that account, so Jenkins won't come back after its
  next restart until you do this.
- Downtime: about 1-2 minutes, because Jenkins is slow to start.
- Shell: elevated PowerShell. Paste each block in order.

> **The big trap: Jenkins' home folder.** The home folder holds every job,
> user and secret. Many installs set it as `%LocalAppData%\Jenkins\.jenkins`,
> which points somewhere different for each account. If you switch the account
> without pinning that path, Jenkins starts with an EMPTY home: the setup
> wizard, no jobs, and the scored login fails. Step 2 pins it.

## 1. Find the service (installs may be weird)

```powershell
Get-CimInstance Win32_Service | Where-Object { "$($_.Name) $($_.DisplayName) $($_.PathName)" -match 'jenkins|java' } |
    Format-List Name, DisplayName, State, StartName, PathName
# What is actually listening on 8080, in case it's not the service you expected:
Get-NetTCPConnection -LocalPort 8080 -State Listen | ForEach-Object { Get-Process -Id $_.OwningProcess | Select-Object Id, Path }
```

- Use the **Name** field, not DisplayName (usually `Jenkins`).
- StartName already `NT SERVICE\...`, `NT AUTHORITY\LocalService` or
  `NT AUTHORITY\NetworkService`: it already runs with low rights. **Stop here.**
- Nothing listed, but 8080 is listening (for example a bare `java -jar
  jenkins.war`): Jenkins isn't a service. Leave it alone and note how it starts.

```powershell
$svc  = 'Jenkins'                  # <-- the Name from above
$acct = "NT SERVICE\$svc"
$s    = Get-CimInstance Win32_Service -Filter "Name='$svc'"
"$svc was running as: $($s.StartName)" | Tee-Object -FilePath "C:\HPCC4\$svc-account-before.txt"
$s.PathName
```

## 2. Find every folder it uses, and pin the home folder

PathName is normally `...\jenkins.exe`, a wrapper. Its settings are in
`jenkins.xml` in the same folder.

If PathName is `nssm.exe` or `java.exe` instead (a hand-made install), there's
no jenkins.xml. The home folder then comes from a `JENKINS_HOME` environment
variable or a `-DJENKINS_HOME=` argument. For nssm, run
`nssm get <name> AppParameters` and `nssm get <name> AppEnvironmentExtra`.

```powershell
$exe     = if ($s.PathName -match '^\s*"([^"]+)"') { $Matches[1] } else { ($s.PathName -split '\s+')[0] }
$install = Split-Path $exe -Parent                     # folder with jenkins.exe / jenkins.xml
$xml     = Join-Path $install 'jenkins.xml'
Select-String -Path $xml -Pattern 'JENKINS_HOME|<executable>|<arguments>|webroot|<logpath>|%'
[Environment]::GetEnvironmentVariable('JENKINS_HOME', 'Machine')             # sometimes set here instead
```

**Find the real home folder** (it holds `config.xml` and a `jobs\` folder):
- Easiest: open http://localhost:8080 and go to **Manage Jenkins > System**. The
  path is at the top, next to "Home directory".
- Or search the usual places:

```powershell
'C:\ProgramData\Jenkins', 'C:\Windows\System32\config\systemprofile\AppData\Local\Jenkins', $install,
'C:\Users\*\AppData\Local\Jenkins', 'C:\Users\*\.jenkins' |
    ForEach-Object { Get-ChildItem $_ -Filter config.xml -Recurse -Depth 2 -ErrorAction SilentlyContinue } |
    Where-Object { Test-Path (Join-Path $_.DirectoryName 'jobs') } | Select-Object DirectoryName
```

**Pin it.** If `JENKINS_HOME` in jenkins.xml contains anything in `%...%`
(`%LocalAppData%`, `%USERPROFILE%`, `%APPDATA%`), replace the value with the
real absolute path. `%BASE%` is fine, because it always means the install folder.
Back up the file first:

```powershell
Copy-Item $xml "$xml.bak"
notepad $xml      # edit: <env name="JENKINS_HOME" value="C:\the\real\path\.jenkins"/>
```

Do the same for `--webroot=` in `<arguments>` if it uses `%LocalAppData%`,
and for `<logpath>` if it uses a `%...%` other than `%BASE%`.

Write down:
- **Home folder**: needs Modify.
- **Install folder** (jenkins.exe, jenkins.war, and logs by default): needs Modify.
- **Java**: the `<executable>` folder needs Read. If it's under
  `C:\Users\...`, this matters.
- **Webroot, or any log folder** outside those: needs Modify.
- **What the backup job touches**: the mysqldump/mysql client (Read) and the
  folder it writes backups to (Modify). Find them in the job's config:

```powershell
$home_ = 'C:\the\real\path\.jenkins'      # <-- the home folder
Select-String -Path "$home_\jobs\*\config.xml" -Pattern '[A-Za-z]:\\[^<"]+' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique
```

## 3. Stop, grant, switch, start

```powershell
$java  = 'C:\Program Files\Eclipse Adoptium\jdk-17'   # <-- folder from <executable>
$read  = @($java)                                     # <-- + mysqldump folder, if any
$write = @($home_, $install)                          # <-- + webroot / log / backup folders, if outside these

Stop-Service $svc -Force
foreach ($d in $read)  { icacls $d /grant "${acct}:(OI)(CI)RX" /T /C /Q }
foreach ($d in $write) { icacls $d /grant "${acct}:(OI)(CI)M" /T /C /Q }
(Invoke-CimMethod -InputObject $s -MethodName Change -Arguments @{ StartName = $acct; StartPassword = '' }).ReturnValue   # 0 = OK
Start-Service $svc
```

A big home folder can take a minute to `icacls`. That's normal.

If `Change` returns something other than 0, use the GUI instead. Run
`services.msc`, open the service's Properties, go to the **Log On** tab and pick
**This account**. Type `NT SERVICE\Jenkins` (with your service name), clear both
password boxes, click OK, then Start.

## 4. Check it works

```powershell
(Get-CimInstance Win32_Service -Filter "Name='$svc'") | Select-Object Name, State, StartName
Start-Sleep 30; (Invoke-WebRequest http://localhost:8080/login -UseBasicParsing).StatusCode     # 200 = up
```

Then in a browser:
1. **Log in** with the scored Jenkins user. If you see the setup wizard, or the
   jobs are missing, the home folder is wrong: Stop the service and fix
   `JENKINS_HOME` (step 2), or roll back.
2. **Run the MySQL backup job** (Build Now) and check it succeeds. It needs
   manifest 172.16.4.40:3306, which the firewall allows.

**Won't start?** Read the wrapper and Jenkins logs in the install folder (or
`<logpath>`). They name the path it couldn't open. Grant Modify on that path
and Start again.

```powershell
Get-ChildItem $install -Filter *.log | Sort-Object LastWriteTime | Select-Object -Last 2 | ForEach-Object { "== $_"; Get-Content $_.FullName -Tail 30 }
```

## 5. Roll back (if it still won't start within a few minutes)

```powershell
Copy-Item "$xml.bak" $xml -Force          # only if you edited jenkins.xml
$s = Get-CimInstance Win32_Service -Filter "Name='$svc'"
Invoke-CimMethod -InputObject $s -MethodName Change -Arguments @{ StartName = 'LocalSystem'; StartPassword = '' }
Start-Service $svc
```

If it ran as a real user before (see `C:\HPCC4\<name>-account-before.txt`), put
that account back in the Log On tab instead. Use the account's current name and
the new password: the built-in Administrator is now `Salty_Goose47`.
