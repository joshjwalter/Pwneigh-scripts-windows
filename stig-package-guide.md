# DoD STIG GPO package (July 2026): what every GPO does

Source: `U_STIG_GPO_Package_July_2026.zip`, reviewed 2026-10-05 by parsing every `registry.pol`,
`GptTmpl.inf` and `audit.csv` in it. Nothing was applied anywhere.

## How the package works (read this first)

- The package holds **44 separate GPO backups**. Each one is a folder named like `{EF870D2C-...}` with a
  `Backup.xml` inside it. `LGPO.exe /g <that folder>` applies **only that one**. You never have to apply
  the whole package, and you don't need to delete anything from it. Copy the folders you want somewhere else.
- **Comp** = computer settings; **User** = per-user settings. **MS** = member server (any non-DC
  server, domain-joined or not). **DC** = domain controller.
- A GPO backup can have up to three parts, and LGPO can apply each one separately:
  - `registry.pol`: registry settings (`LGPO /m`, or `/u` for user)
  - `GptTmpl.inf`: passwords, lockout, account renames, user rights (`LGPO /s`)
  - `audit.csv`: audit logging (`LGPO /ac`)
- There are **two copies** of the OS baselines:
  - **Main folders** (`DoD WinSvr 2022 MS and DC v2r9\GPOs\...`) are meant for importing into Active Directory.
  - **`Support Files\Local Policies\...`** is DISA's version for **standalone machines via LGPO**. That's you.

  The main OS versions are dangerous on a standalone box (see the warning below).

> **WARNING: never apply a main-folder OS GPO with LGPO on a non-domain box.** Its user rights say
> "Deny log on through Remote Desktop" for `S-1-5-113` (= **every local account**), plus literal
> placeholder text `ADD YOUR DOMAIN ADMINS`. Result: **no local account can RDP in**. The Local Policies
> copy only denies the Guests group.

---

## Every GPO in the package

Settings counts are computer registry / user registry / security template / audit lines.

### Windows Server OS baselines

| GPO | Settings | What it does |
|---|---|---|
| **Local Policy DoD WinSvr 2022 MS STIG Comp v2r9** `{EF870D2C}` | 58 / – / 84 / 24 | The full Server 2022 hardening baseline for a standalone server. Details below. |
| **Local Policy DoD WinSvr 2025 MS STIG Comp v1r2** `{ECE37090}` | 51 / – / 81 / 24 | Same for Server 2025. Differences from 2022: **no minimum password length**, no WDigest setting (already off by default on 2025), smaller Security log (192 MB vs 5 GB). |
| Local Policy DoD WinSvr 2025 MS STIG User v1r2 `{4464FCF7}` | – / 2 / – / – | Two user settings: keep "downloaded from internet" marks on files, and block `AlwaysInstallElevated` (a well-known privilege escalation). Harmless and useful. |
| Local Policy DoD WinSvr 2019 MS STIG Comp v3r9 `{B1A0BD38}` | 66 / – / 84 / 25 | Server 2019 version, nearly identical to 2022. |
| Local Policy DoD WinSvr 2016 MS STIG Comp v2r10 `{581EB8D2}` + User `{D7BE5830}` | 62 / 2 / 84 / 22 | Server 2016 version. |
| Local Policy DoD WinSvr 2012 R2 MS STIG Comp v3r7 `{1338573D}` + User `{BF27349D}` | 145 / 13 / 105 / 20 | Server 2012 R2 version. The User GPO adds a password-protected screensaver and turns off the preview pane, among others. |
| DoD WinSvr 2022 **MS** STIG Comp v2r9 `{CD80AEFB}` (domain) | 71 / – / 85 / 24 | The domain version of 2022 MS. Same as the Local Policy one **plus**: deny RDP/network logon for **all local accounts**, the domain-admin placeholders, LAPS, Credential Guard/VBS/HVCI, hardened SYSVOL/NETLOGON paths, and only 4 cached logons. **Not for standalone boxes.** |
| DoD WinSvr 2025 **MS** STIG Comp v1r2 `{FCE44C04}` + User `{161F51DC}` (domain) | 67 / 2 / 83 / 24 | Domain version of 2025 MS. Same caveats. |
| DoD WinSvr 2019 / 2016 / 2012 R2 **MS** (domain) | — | Domain versions of the older OSes. Same caveats. |
| DoD WinSvr 2022 **DC** STIG Comp v2r9 `{A9FE9CE6}` | 67 / – / 93 / 27 | Domain controller baseline: the MS settings plus DC-only hardening (LDAP signing, Kerberos, DC user rights). Has the `ADD YOUR DOMAIN ADMINS` placeholders, which must be edited before use. |
| DoD WinSvr 2025 **DC** Comp `{5C75ACAE}` + User `{C66B6F9A}` | 58 / 2 / 77 / 27 | 2025 DC baseline. Note: it does **not** set account lockout. |
| DoD WinSvr 2019 / 2016 / 2012 R2 **DC** (Comp + User) | — | DC baselines for older OSes. |

### Windows workstation baselines

| GPO | What it does |
|---|---|
| Local Policy DoD Windows 11 Computer STIG v2r8 `{8315AFB5}` + User `{5B163549}` | Win 11 hardening for standalone PCs. Same themes as the server baseline (renames Administrator, 3-try lockout, FIPS, transcripts, SmartScreen Block). The User GPO turns off Copilot, lock-screen toasts and third-party suggestions. |
| Local Policy DoD Windows 10 STIG Comp v3r6 `{561398EB}` + User `{29169D3D}` | Same for Win 10. |
| DoD Windows 11 / Windows 10 Computer + User (domain) | Domain versions. Deny network and RDP logon to all local accounts. **Not for standalone.** |

### Security products

| GPO | What it does |
|---|---|
| **DoD Microsoft Defender Antivirus STIG Computer v2r9** `{1AF7AB30}` | 52 registry settings, all for Defender: <br>• Turns on real-time, script, email, removable-drive and packed-exe scanning; cloud "block at first sight" at high level; potentially-unwanted-app (PUA) blocking; Network Protection (blocks known-bad domains), also on Windows Server. <br>• **Locks Defender against local admins**: local exclusions are ignored and the exclusion list is hidden, so an attacker with admin can't just add `C:\` as an exclusion. <br>• **Attack Surface Reduction rules in BLOCK mode**: credential stealing from LSASS (mimikatz-style), **webshell creation on servers**, **potentially obfuscated scripts**, JS/VBS launching downloaded exes, unsigned exes from USB, abuse of vulnerable signed drivers, advanced ransomware protection, and Office/email child processes. <br>• ASR in **AUDIT only** (logs, doesn't block): PsExec/WMI process creation, WMI persistence, and exes that aren't prevalent or trusted. |
| **DoD Windows Defender Firewall STIG v2r2** `{EB82B913}` | 21 settings. Firewall on, inbound **block**, **outbound ALLOW** (all profiles); logging of dropped and allowed connections (16 MB log). On the **Public profile it sets `AllowLocalPolicyMerge = 0`**: every local rule (including `HPCC4-Keep-TCP-3389` for RDP) is **ignored**, and the GPO has no allow rules of its own. **RDP lockout on any VM whose network is "Public"** (most non-domain VMs). It also undoes the script's outbound lockdown. |

### Applications

| GPO | What it does |
|---|---|
| DoD Google Chrome STIG Computer v2r11 `{EAB6D3D1}` | 51 settings: no password manager, no sync, block pop-ups and geolocation, safe search provider, no background apps, extension restrictions. Only matters if Chrome is installed. |
| DoD Microsoft Edge STIG Computer v2r5 `{AC3FEC54}` | 64 settings: no sync or import, SmartScreen can't be bypassed, **DevTools disabled**, no InPrivate, can't delete history. |
| DoD Mozilla Firefox STIG v6r8 `{BAB08532}` | 45 settings: TLS 1.2 minimum, no password manager or form history, extension updates locked. |
| DoD Internet Explorer 11 STIG Computer `{12431AD5}` + User `{2DC254B0}` | 136 + 5 settings locking down IE zones, downloads and add-ons. IE is legacy; little value. |
| DoD Office 2019-M365 Apps STIG Comp `{37EB9686}` + User `{B3DE9937}` | 201 + 137 settings: macro blocking, Protected View, blocked file types, add-in restrictions. Only matters if Office is installed. |
| DoD Adobe Acrobat Reader DC / Pro DC (Computer + User, 4 GPOs) | ~20 settings each: Protected Mode, Enhanced Security, no JavaScript-driven web access, FIPS mode (Pro). Only matters if Acrobat is installed. |

---

## What the Server 2022/2025 standalone baseline actually changes

**Helpful in a competition:**
- **SMB:** SMBv1 removed (server + client driver disabled). SMB signing **required** both ways. No insecure guest SMB.
- **Credentials:** WDigest off (no clear-text passwords in memory, on 2022). No LM hashes. **NTLMv2 only** with 128-bit (`LmCompatibilityLevel = 5`). Kerberos AES only.
- **Anonymous access:** no anonymous SID/share enumeration, no null sessions, remote SAM queries restricted to Administrators.
- **Privilege escalation:** `AlwaysInstallElevated = 0`, UAC on (built-in Administrator included), Windows Installer user control off.
- **Remote access:**
  - RDP: always prompt for password, high encryption, encrypted RPC, no drive redirection, no saved passwords.
  - WinRM: no Basic auth, no unencrypted traffic, no RunAs.
  - RPC: unauthenticated clients restricted.
- **Logging (great for spotting red team):**
  - 24 audit subcategories, plus the full command line on every process creation
  - PowerShell **script block logging** and **transcription**
  - 5 GB Security log on 2022 (192 MB on 2025)
- **Misc:** autorun/autoplay off, SmartScreen set to Block, ICMP redirects and source routing off.

**Will bite you in a competition:**

| Setting | Effect | Recommendation |
|---|---|---|
| `NewAdministratorName = "X_Admin"`, `NewGuestName = "Visitor"` | **Renames** the built-in Administrator. You (and maybe the scoring engine) log in as `Administrator` and fail. | **Done:** Guest line removed; Administrator renamed to your own name instead (see Decisions). |
| `LockoutBadCount = 3` (15 min) | 3 wrong passwords lock an account for 15 minutes. Red team can **lock out your scored service accounts on purpose**. Don't count on the built-in Administrator being exempt: newer Windows builds can lock it out over the network. | Set to `0` (off) or raise it, e.g. `10`. Strong passwords are your real defense. |
| `MinimumPasswordLength = 14` + complexity + 24-password history (2016–2022) | Passwords the script sets must be 14+ characters and complex, or `Set-LocalUser` fails. | Keep, but pick compliant passwords. |
| `FIPSAlgorithmPolicy = 1` | FIPS-only crypto. Can break older ASP.NET apps, some RDP/SSH clients and anything using MD5/RC4. | **Remove** unless you've tested every scored service with it on. |
| `SeImpersonatePrivilege` = Admins + service accounts only | Drops `IIS_IUSRS` if IIS added it, which **may break IIS app pools**. | Test IIS sites after applying, or remove this line. |
| `SeInteractiveLogonRight = Administrators` | Only admins can log in at the console. Non-admin scored users can't log in locally (RDP is unaffected). | Remove if a scored check logs in interactively as a normal user. |
| SMB signing required, NTLMv2-only | Old SMB/NTLM clients (an old scoring engine, a Linux box running an old Samba client) can't connect. | Usually fine. Re-check scored SMB after applying. |
| PowerShell transcription → `C:\ProgramData\PS_Transcript` | **Everything you type in PowerShell is saved to disk**, including the script's output. Any local user can likely read it. `-Cleanup` doesn't delete this folder. | Keep it for detection, but know it's there. Delete that folder in `-Cleanup` if you care. |
| `InactivityTimeoutSecs = 900` | Console locks after 15 minutes idle. | Fine. |
| DoD legal banner | Banner shown at every logon. | Fine. |

**Things your checklist assumes the GPO does, but it doesn't:**
- **RDP Network Level Authentication is not set by ANY GPO in this package** (no `UserAuthentication`
  value anywhere). The script now turns it on itself (`Set-RdpNla`).
- The built-in Administrator is **renamed, not disabled**. The checklist §6 already says this.
- Server 2025's baseline has **no minimum password length** setting.

---

## Decisions (2026-10-07) - what is actually implemented

- **Bundle**: `build-gpo-bundle.ps1` builds it from the package. It contains only the Local Policies
  member-server baselines for **Server 2012 R2, 2022 and 2025**, plus the **Defender STIG**. No firewall STIG,
  no domain-version OS GPOs, no DC/workstation/browser/Office GPOs.
- **Edits to the OS baselines** (all listed in the bundle's `CHANGES.md`):
  - **FIPS removed**.
  - Built-in Administrator renamed to **a custom name** (`-AdminName`, default a random one like
    `Big_Boy79`), not `X_Admin`.
  - Guest rename removed.
  - `SeImpersonatePrivilege` removed (revisit once the packet says whether IIS is scored).
  - 2012 R2 only: `SeRemoteInteractiveLogonRight` and all firewall policy removed.
- **Kept**: lockout after 3 bad attempts for 15 minutes; everything else as DISA shipped it.
- **AV**: Defender + the Defender STIG (no 360 Total Security). 2012 R2 has no Defender, so it gets no AV STIG.
- **On the box**: `Install-DodGpo` picks the baseline by OS build (member servers only), backs up the local
  policy once to `C:\HPCC4\gpo-before`, applies, then deletes the bundle. It runs after the firewall,
  password and tools steps.

---

## Recommendations (original review; 1, 2, 3, 4 and 8 are now implemented as above)

1. **Apply GPOs one at a time, chosen per box. Never point LGPO (or `$DodGpoDir`) at the whole package.**
   `Install-DodGpo` currently applies every `Backup.xml` under `$DodGpoDir`. Pointed at the package
   root, that would apply all 44 GPOs: DC + workstation + Office + firewall, conflicting with each other.
   Change it to take an explicit list of GPO folders.

2. **For each Windows Server box, apply exactly these:**
   - `Support Files\Local Policies\DoD Windows Server <your version> MS ...\GPOs\{Comp GUID}`.
     Use a **competition copy** whose `GptTmpl.inf` has the rename lines removed, lockout off or raised,
     and FIPS removed. Also drop the `SeImpersonatePrivilege` line if the box runs IIS.
   - The matching Local Policy **User** GPO if your OS has one (2025, 2016, 2012 R2). Small and harmless.
   - **Defender AV STIG**, *if Defender is your antivirus* (see 4).

3. **Skip the firewall STIG.** It locks out RDP on Public-profile VMs and reverts outbound to allow. The
   script already does a stricter firewall. If you want the STIG's one good part (logging dropped
   connections), add it locally:
   `Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384`.

4. **Defender STIG vs 360 Total Security: choose one.** A third-party AV switches Defender off, and then the
   Defender STIG (including its ASR rules) does nothing. I'd pick **Defender + this STIG**:
   - It's built in, with no internet download.
   - Its ASR rules block LSASS credential theft and webshells.
   - Local admins can't add exclusions.

   **Caution:** its "block potentially obfuscated scripts" rule is in block mode. The plan in
   `PROD-TODO.txt` to run the script through Invoke-Obfuscation will very likely get **your own script
   blocked**. Either don't obfuscate, or test the obfuscated build with this STIG applied.

5. **Domain controllers:** don't apply the DC GPOs at the competition unless you've first edited the
   `ADD YOUR DOMAIN ADMINS` placeholders and tested it. The DC baselines also weren't reviewed setting by
   setting here (LDAP signing etc. could break scored LDAP). The script already skips most steps on DCs.

6. **Workstations (Win 10/11), if any:** the Local Policy Win 10/11 Comp + User GPOs, with the same
   `GptTmpl.inf` edits as servers.

7. **Skip** Chrome, Edge, Firefox, IE11, Office and Adobe GPOs unless that app is installed **and** is part
   of a scored service. They protect a desktop user browsing the web, which isn't your threat on a
   scored server. Note the Edge GPO disables DevTools.

8. **Do these by hand or in the script, because no GPO does them:**
   - RDP NLA on
   - Firewall: inbound and outbound (the script does this)
   - Changing the actual passwords
   - Deleting backdoor accounts
   - The persistence sweep
   - Disabling the built-in Administrator, if you want that, after confirming another admin works

9. **Order on the box:**
   1. Run the script (backup + firewall first).
   2. Apply the GPOs.
   3. **Immediately test a new RDP login** from a second session before closing your current one.
   4. Check every scored service.
   5. Snapshot the VM.

   Rehearse this on a test VM first. `reset-hpcc4.ps1` restores the policy saved in `C:\HPCC4\gpo-before`,
   but only best-effort (some settings stick), so snapshot first and revert the VM for a truly clean slate.
