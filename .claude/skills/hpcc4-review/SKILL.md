---
name: hpcc4-review
description: Background knowledge for reviewing changes to hpcc4-simple.ps1 before it's run for real. Applies whenever the user is about to run, or asks whether it's safe to run, hpcc4-simple.ps1 against a live/scored machine.
user-invocable: false
---

# Reviewing hpcc4-simple.ps1 before a real run

`hpcc4-simple.ps1` is a defensive hardening script for CCDC-style scored competitions. It is
destructive by design: it deletes local accounts not in `$AuthorizedUsers`, resets local
passwords, rewrites firewall rules, and locks ACLs on `$LockPaths`. There is no undo for
password changes (`reset-hpcc4.ps1` says so explicitly — old passwords are never stored).

Before recommending or helping run it for real (not `-DryRun`), check:

1. **Tunables block (lines ~5-26) is filled in for *this* competition**, not left over from a
   previous one. In particular:
   - `$AuthorizedUsers` — if empty, *every* non-built-in local account gets deleted. Confirm
     that's actually intended before proceeding.
   - `$ExcludeUsers` — accounts whose passwords must not change; cross-check against any
     service/scheduled-task accounts the user has mentioned.
   - `$AllowTcp` / `$AllowUdp` / `$BlockTcp` / `$BlockUdp` — should match the scored services in
     the current competition packet, not a prior one.
   - `$KeepOpenTcp` — must include whatever port the operator is actually connected over, or the
     run can lock them out.
2. **A `-DryRun` pass has been run first** and its output reviewed, unless the user explicitly
   says they've already done that for this exact tunables configuration.
3. **If `$DodGpoDir`/`$LgpoExe` are set**, remind the user to follow up with the
   `gpo-verify` skill / `gpo-verification-checklist.md` afterward — GPO application isn't
   verified by the script itself.
4. **If this is being run against a machine the user is remoted into**, flag the `$KeepOpenTcp`
   point explicitly — this is the most common way this class of script locks out the operator.

When the user is only editing the script (not about to run it), don't force this checklist on
them — just keep it in mind and raise anything that looks like a leftover value from a previous
run (e.g., a competition-specific IP or hostname hardcoded where a tunable should be).
