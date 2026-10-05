# Completion evidence

Recovered A plus dirty runtime/recovery/accounts/GPO work into `codex/review-complete`, based on reviewed foundation `272b36b`. Primary checkout, spare worktrees, stashes and external original tests were preserved; recovered originals matched their bounded backups at final inspection.

Native Windows verification, 2026-10-04, pinned Pester 5.9.1:

| Engine (x64) | Ordinary | Harmless children | Compiler only | Process exits |
| --- | ---: | ---: | ---: | --- |
| Windows PowerShell 5.1.26100.9444 | 294/294 | 17/17 | 1/1 | 0 / 0 / 0 |
| PowerShell 7.6.5 | 294/294 | 17/17 | 1/1 | 0 / 0 / 0 |

No failed containers/blocks, skips, not-run or inconclusive tests in these passing runs. Each selection uses a fresh process; compiler APIs are never invoked. The runner disables unused HKCU TestRegistry creation. Host-changing calls are mocked/default-denied; permitted real I/O uses verified disposable fixtures. Full selections are in [tests/README.md](tests/README.md).

Regressions cover combined cancellation/finally faults, immutable originals and restore conflicts, failed controls/preflight, SID refresh and late dependencies, raw registry kinds, tool prerequisites and explicit GPO manifests/order, persistence payloads/identity disposal, watcher gaps and hook interfaces. Parser checks and `git diff --check` also passed. Source is UTF-8 BOM with enforced CRLF checkout for PS5.1 and byte-pinned fixtures.

Windows CI uses the same three explicit selections for both engines: [completion-branch workflow runs](https://github.com/joshjwalter/Pwneigh-scripts-windows/actions?query=branch%3Acodex%2Freview-complete). PR checks are authoritative for the published revision.

Unit/CI success does not establish live Server enforcement of firewall/RDP/DHCP, ACLs, GPO or Sysmon. No hardening/reset/installer/event/history/deletion actions were exercised against the development host. Safe automatic reset is limited to captured supported ACL/registry resources; unsupported policy/content/service rollback and uncertain/conflicting states retain their originals for manual review. Nothing was merged or deployed.
