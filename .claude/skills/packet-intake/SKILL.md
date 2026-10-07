---
name: packet-intake
description: Use when the user shares the HPCC4 competition packet, team packet, rules of engagement, scoring info or box list (PDF, doc, image or pasted text). Walks the packet against everything that changes how hpcc4-simple.ps1, the GPO bundle and the plan run, and produces the list of things to change, add, or ask about.
---

# Competition packet intake

The user has shared the competition packet. Turn it into a list of every script setting, bundle change and decision
the packet affects. **Do not edit any file in this step.** Tunables drive irreversible actions (account deletion,
password resets, firewall lockout). Present the list, then wait for the user to confirm each change.

## Steps

1. Read the **whole** packet, including appendices, network diagrams and screenshots. Take notes **per box**.
2. Read the current tunables block of `hpcc4-simple.ps1` (top of file) and `build-gpo-bundle.ps1`'s `$Sources` /
   `$InfRemovals`, so you compare against what is there now, not what you remember.
3. Walk **every** item in the checklist below. For each one, say what the packet says, or "not in packet".
4. Output, in this order:
   1. **Must change**: a table of `Packet says` | `Change (setting or file)` | `Why it matters`, grouped per box.
   2. **Decisions for you**: trade-offs the user has to pick (e.g. NLA vs an old scoring client).
   3. **Not in the packet, so ask the organizers**: anything on the checklist that the packet leaves open
      **and** that could break scoring or lock the team out.
   4. **Draft tunables per box**: a fenced PowerShell block of the filled-in tunables. Mark it as a draft and
      don't write it to disk.
   5. **Rehearsal notes**: what to test on a VM before comp day because of this packet.
5. Once the user confirms, make the edits. The tunables hook will ask for approval on each one.

## Checklist (anything that can change how the script runs)

### Boxes and OS
- [ ] Number of boxes, hostnames, IPs, and which ones are yours vs out of scope.
- [ ] OS and version **per box**. The bundle only has Server **2012 R2 / 2022 / 2025** member-server baselines.
      Server 2016/2019 or Win 10/11 need a new `$Sources` entry in `build-gpo-bundle.ps1` and a build number in
      `Get-StigGpoFolder` (2016 = 14393, 2019 = 17763; Win 10/11 also need ProductType 1 handling).
- [ ] Domain controller, domain member or standalone? A DC skips the firewall purge, outbound lockdown, account
      removal, passwords and the OS GPO. A member server needs its DCs reachable: `$AllowOutHosts`, or confirm
      the auto-detect via the domain's DNS will work.
- [ ] PowerShell version. 2012 R2 ships PS 4.0 and the script exits; it needs WMF 5.1 (KB3191564) **and a
      reboot**. Is installing it allowed, and is the installer available offline?
- [ ] Is Defender installed? 2012 R2 has none, so no Defender STIG there and another AV is needed
      (installed by hand: the script no longer downloads one). Is third-party AV allowed?

### Access to the box
- [ ] Console access, or RDP only? With RDP only, a lockout (3 bad attempts / 15 min), NLA problems or a firewall
      mistake means no way back in. Can the organizers reset or revert a box, and is there a penalty?
- [ ] RDP port (the script reads the live one). Do you or the scorer use SSH (22) or WinRM (5985/5986)?
      Put those in `$KeepOpenTcp`.
- [ ] How do files get onto the box: copy/paste, a download, RDP drive redirection, a share? **The STIG
      disables RDP drive redirection**, so copy everything over before the GPO step. If it's a download,
      internet access is required (see Outbound).
- [ ] VM snapshots or reverts: allowed? Do they cost points?

### Accounts
- [ ] **Scoring user name.** Put it in `$AuthorizedUsers`, or the script **deletes** it. If its password must not
      change (or must be submitted when changed), add it to `$ExcludeUsers` or plan the submission.
- [ ] The full authorized-user list **per box** goes in `$AuthorizedUsers`. Every other account with RID ≥ 1000
      is deleted.
- [ ] Admin accounts provided, and their initial credentials.
- [ ] Password-change rules: submission format and deadline, whether one password for every account is allowed
      (`Set-LocalPasswords` sets the same one on every target), and any accounts that must not change.
- [ ] Password requirements vs the STIG: the STIG requires 14 characters, complexity, 24 remembered passwords and
      a minimum age of 1 day. Passwords set before the GPO aren't re-checked, but later changes must comply.
- [ ] Any rule against renaming or disabling accounts. The bundle renames the built-in Administrator to the
      `-AdminName` in `gpo-bundle\CHANGES.md`. Does anything (the scorer, an inject, the organizers' access) log
      in as `Administrator`?
- [ ] Lockout 3 / 15 min: red team can lock out the scorer's account by spraying it, which costs uptime. Decide
      whether to keep 3 or raise it (`LockoutBadCount` in the OS GptTmpl.inf, via the builder).
- [ ] Service, IIS app-pool and scheduled-task accounts (the script protects in-use ones automatically, but
      list them).
- [ ] Do normal (non-admin) scored users log in **at the console**? The STIG limits local logon
      (`SeInteractiveLogonRight`) to Administrators.

### Scored services
- [ ] Every scored service, with port and protocol, **per box**: put them in `$AllowTcp` / `$AllowUdp`. `$AllowTcp`
      defaults to `3389`; remove it if RDP isn't scored and you don't want it reachable after the run.
- [ ] **ICMP / ping checks.** The script has **no** ICMP allow rule, so inbound default-block drops ping. If ping is
      scored, an ICMP echo rule is needed. That's a script change.
- [ ] IIS / web: which sites, app pools and .NET version. Decide on `SeImpersonatePrivilege` (the bundle
      currently strips it), whether to add the IIS STIG GPOs, web root to `$BackupPaths`, and outbound to the DB.
- [ ] SQL Server: port, instance, service accounts, and DB files to back up. The GPO package has no SQL STIG.
- [ ] DNS, AD, DHCP, FTP (passive port range!), SMB shares, mail (25/110/143/587/993), SSH, others.
- [ ] **How the scorer checks each service.** The STIG breaks: anonymous or guest SMB, SMBv1, NTLMv1/LM,
      WinRM Basic or unencrypted auth, remote admin with a non-RID-500 local admin (UAC remote token filtering),
      and old TLS clients. RDP checks must support NLA.
- [ ] Content or uptime checks that write to files: never put those files in `$LockPaths`.

### Outbound (default-BLOCK after the run)
- [ ] What each box connects **out** to: web→DB, app→API, DNS forwarders, NTP server, mail relay, AD/DCs, the
      scoring engine (push-style checks), and update/AV servers. Set `$AllowOutTcp` / `$AllowOutUdp` /
      `$AllowOutHosts`.
- [ ] Is there internet access at all? It decides whether `$ToolsZip` is a URL or a local path, whether Defender
      signatures can update, and whether `$AllowOutTcp` needs 80/443.
- [ ] Is blocking outbound, or blocking by IP (red team ranges), allowed by the rules?

### Rules of engagement
- [ ] Are STIG/GPO hardening, firewall changes and disabling services allowed? Are any services or settings
      explicitly off-limits?
- [ ] Is **clearing event logs** allowed? `-Cleanup` wipes **all** of them. Do injects or incident reports need
      logs? The STIG also writes PowerShell transcripts to `C:\ProgramData\PS_Transcript`.
- [ ] Are third-party tools allowed: Sysinternals, Sysmon (`$InstallSysmon`), AV?
- [ ] Are reboots allowed? WMF 5.1 needs one.
- [ ] Is there a grace period before red team starts, and is scoring live from minute one? This affects whether
      to rehearse a faster run order.
- [ ] Injects: anything needing reports (the persistence report is in `C:\HPCC4\persistence.txt`), user
      creation, or service changes the script would undo (e.g. a new user that's not in `$AuthorizedUsers`
      gets deleted on a re-run).

### Files and paths
- [ ] What to back up (`$BackupPaths`): web roots, configs, DB files, scored content.
- [ ] What to lock (`$LockPaths`): hosts file and static configs only, never something the app writes.
- [ ] Drive letters and free space. Do `C:\Tools` / `C:\HPCC4` collide with anything?

### Extra services
- [ ] Services the packet names as unneeded or dangerous: put them in `$DisableServices`. Never a scored one.

## Reminders to include in every answer
- Rebuild the bundle with the **same** `-AdminName` (see `gpo-bundle\CHANGES.md`) whenever `build-gpo-bundle.ps1` changes.
- Rehearse the whole run on a snapshotted VM of the same OS with the packet's settings, then run the
  `gpo-verify` skill, then `reset-hpcc4.ps1` or revert the snapshot.
- Don't run any of the scripts on the dev box.
