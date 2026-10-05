# HPCC4 Windows competition startup

Deploy **hpcc4-simple.ps1 alone**, with its editable tunables, exact identity marker and guarded entry intact. Use elevated Windows PowerShell 5.1 x64; PowerShell 7.5+ is also supported. Configure accounts, scored ports, exclusions, services and packages for the actual competition before running. `-DryRun` performs reads and prints plans with zero mutation. Dot-sourcing loads definitions and returns control to the caller.

The script protects the live RDP port and configured keep ports before authorized firewall changes. A missing completed firewall backup prohibits purge; independently authorized default-block still requires valid effective controls. DC rules/defaults are preserved. Block rules, GPO merge restrictions and incomplete observations can prevent access recovery; the result reports failure instead of promising availability.

Accounts use the current token SID, service/task/IIS dependencies and conservative domain-name exclusions. Approval freezes SID/name pairs, which are refreshed after prompts and before every write. Passwords remain a shared-password workflow and must be submitted to the scoreboard. Password changes and deleted SIDs cannot be rolled back.

Recovery originals and the exclusive writer live under an OS-derived protected `System32\config\HPCC4-Recovery` bootstrap, keyed by machine and output directory. Content copies, firewall exports and full persistence reports remain in `$OutDir`. Reused writable/unverified storage is refused. Preserve pending records and partial artifacts for manual inspection; never turn them into trusted originals.

Accepted tools are staged in protected per-run directories under `$ToolsDir`. Optional archive SHA256 and AV signer policy remain optional. Without a pinned archive, executable roles require valid signatures. Package, AV, Sysmon and LGPO outcomes are separate. Failed requested archives do not publish PATH/EULA or run stale tools. Machine PATH retains its original registry kind and raw contents; the current session PATH is unchanged.

Tools precede GPO. Supply an actual reviewed ordered `$DodGpoSelection` manifest and trusted LGPO, as described in [gpo-selection-contract.md](gpo-selection-contract.md). No package roles are inferred from GUIDs. Every selected byte is copied into protected staging and revalidated before import. A checked local-policy backup precedes imports; refresh/import success is separate from effective policy observation.

`-Unlock` restores only validated exact-file ACL/attribute originals. `reset-hpcc4.ps1` prompts before restoring captured ACL and PATH/EULA resources; it preserves backups, preexisting assets and later conflicting changes. Sysmon configuration, blanket firewall/GPO policy and content restores require manual review because safe current-applied-state rollback is not captured. Neither companion deletes directories.

Optional `-Cleanup` reports independent history and per-log outcomes. History saving stays `SaveNothing`. Exact deployed-file removal uses a hidden trusted PowerShell child with six bounded attempts, same-handle file identity/digest checks and replacement refusal. Scheduling is acknowledged separately from deletion completion. Other sessions, copies, external traces and protected recovery inputs remain.

`watch-hpcc4.ps1` is read-only and guarded. It tracks SID/configuration identities, typed observations and last-good gaps; its critical-hash list defaults to empty. Opted-in hashes have file/count/byte bounds. Polling misses transient or same-metadata changes, and failed reads are never reported as unchanged.

Run only the explicit guarded test selections in [tests/README.md](tests/README.md). Unit/CI evidence does not establish live Windows Server firewall, ACL, GPO, DHCP or Sysmon enforcement. No development or ordinary CI test executes hardening, reset, installers, event clearing or deferred deletion against its host.
