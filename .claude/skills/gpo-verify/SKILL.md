---
name: gpo-verify
description: Run every Verify check from gpo-verification-checklist.md against the current machine and report pass/fail. Use after running Install-DodGpo (or any GPO refresh/gpupdate) to confirm the STIG settings actually took effect, instead of running each PowerShell one-liner by hand.
---

# GPO verification runner

`gpo-verification-checklist.md` (repo root) lists settings that used to be set directly by
`hpcc4-simple.ps1` but were removed because the DoD STIG GPO now applies them. Each numbered
item has a fenced ` ```powershell ` block under **Verify** and an **Expect** line stating the
value that means the GPO applied correctly.

## Steps

1. Read `gpo-verification-checklist.md` from the repo root.
2. For each numbered section that has a **Verify** code block:
   - Extract the PowerShell command(s).
   - Run them elevated (Administrator) on the target machine via the PowerShell tool. If not
     running elevated, tell the user up front — several checks (registry under
     `HKLM\SOFTWARE\Policies\...`, `Get-SmbServerConfiguration`) will silently return empty or
     throw access-denied instead of failing loudly.
   - Compare the actual output to the **Expect** text right after the block.
3. Also run the one-off checks called out under "Still in the script on purpose" if the user
   asks about firewall policy merge — that one requires the GPO's GUID, ask the user for it
   (`LGPO.exe /parse /m "<GUID>\DomainSysvol\GPO\Machine\registry.pol" | Select-String
   "WindowsFirewall","AllowLocalPolicyMerge"`) rather than guessing it.
4. Report a table: `#` | setting | expected | actual | PASS/FAIL. For any FAIL, quote the
   relevant "Consequence" or note from the checklist (e.g. item 6's built-in Administrator
   caveat is expected behavior, not a failure — call that out explicitly rather than flagging
   it red).
5. If the checklist file has been edited since this skill was last used (new sections added),
   verify those too — don't rely on a hardcoded list of checks.

Do not modify the target machine's configuration as part of this skill — it is read-only
verification. If a check fails, report it; don't try to fix it unless the user asks.
