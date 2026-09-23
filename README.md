# hpcc4-simple.ps1

A first-run script for defending Windows Server boxes in HPCC4, a UCF blue-team competition. It does five jobs:
- back up files
- lock down the firewall
- change local passwords
- install your tools zip (and optionally Sysmon)
- make chosen files read-only

It runs on Windows PowerShell 4.0–5.1, on Server 2012 R2 through 2025. Every change is logged to `C:\HPCC4\log.txt`, and one failed step never stops the rest.

## 1. Fill in the tunables (top of the script)
- [ ] `$KeepOpenTcp`: ports that stay open **for the whole run**, along with the live RDP port (always kept). The default is 22 (SSH).
- [ ] `$AllowTcp` / `$AllowUdp`: every **scored** port, e.g. 80, 443, 21, 3306, 445. **Put DNS in `$AllowUdp` (53).** These are opened **at the end** of the run.
- [ ] `$BlockTcp` / `$BlockUdp`: ports the packet says to close. The script refuses to block an allowed, keep-open or RDP port.
- [ ] `$ExcludeUsers`: **the scoring accounts, app pool identities, and any account the scoring engine logs in with.** Service, app pool and task accounts are also detected and skipped automatically.
- [ ] `$BackupPaths`: web roots and config files from the packet.
- [ ] `$LockPaths`: **only files that no scored service writes to.** Never lock a web root, upload folder or database folder.
- [ ] `$ToolsZip`: a local path or https link to your tools zip, e.g. your GitHub release, or `https://download.sysinternals.com/files/SysinternalsSuite.zip`. Also set `$ToolsZipSha256` (for your own zip), and `$InstallSysmon` if the zip contains `Sysmon64.exe` and `sysmonconfig.xml`.

## 2. What the firewall does
1. **Start of the run:** it saves the whole firewall policy to `C:\HPCC4\firewall-before.wfw`. Then it adds the RDP and `$KeepOpenTcp` rules, and only after that **removes every other inbound rule** except Windows' built-in DHCP rules. Inbound traffic is blocked by default and the firewall is turned on. Outbound rules are never touched.
2. **End of the run:** it opens `$AllowTcp` / `$AllowUdp` and adds the block rules. This runs even if a step fails or you press Ctrl+C.

**Scored services are down between those two points**, which includes the password prompts. Answer the prompts quickly.
- **Nothing is removed if** the box is a domain controller (AD needs dynamic ports), if the firewall backup is missing, or if you answer `N` when warned about uncovered ports. In those cases it only adds its own `HPCC4-*` rules.
- **To undo it all:** `netsh advfirewall import C:\HPCC4\firewall-before.wfw`

## 3. Run it (from an elevated PowerShell)
1. `.\hpcc4-simple.ps1 -DryRun`: prints `WOULD:` lines and changes nothing. Any listening port marked "will be blocked once the firewall is on" must go in `$AllowTcp`/`$AllowUdp`, or it stays closed.
2. `.\hpcc4-simple.ps1`: the real run.
3. **Check RDP from a new session.** The session you're in stays open even if RDP is now blocked. Then check every scored service.
4. Submit the password changes to the scoreboard.

Start every scored service **before** you run it. The port check only sees ports that are listening at that moment.

## `-Unlock` (panic button for file locks)
`.\hpcc4-simple.ps1 -Unlock` restores the ACLs saved before locking. Then it clears the read-only attribute and renames each save file to `*.restored`. Running the lock twice is safe: the original ACL is saved only once.

## Know the limits
- **The lock is friction, not a wall.** An attacker with admin rights can remove it.
- **Backups live on the same box** (`C:\HPCC4\backup\...`). Copy anything critical off it by hand.

## Test on a Windows VM first
1. `.\hpcc4-simple.ps1 -DryRun`: only `WOULD:` lines.
2. `.\hpcc4-simple.ps1`: a real run.
3. Try to edit `C:\Windows\System32\drivers\etc\hosts` as admin. **Saving should fail.**
4. `.\hpcc4-simple.ps1 -Unlock`
5. Edit the hosts file again. **Saving should work.**

**To start over:** run `.\reset-hpcc4.ps1` (test VMs only; type `RESET` to confirm). Keep it in the same folder as `hpcc4-simple.ps1`. If you renamed or moved the main script, pass its path: `.\reset-hpcc4.ps1 -MainScript .\my-copy.ps1`. The reset script:
- restores the firewall from `firewall-before.wfw`
- unlocks files
- uninstalls Sysmon
- removes `C:\Tools` from PATH
- clears the Sysinternals EULA flag
- **deletes `C:\Tools`**

It can't undo password changes; set those back by hand. Backups and logs in `C:\HPCC4` are kept.

Unit tests (Pester 5, all mocked, safe to run without elevation): `Invoke-Pester .\tests\hpcc4-simple.Tests.ps1`
