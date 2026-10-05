# Guarded native Windows tests

Use Pester **5.9.1**, Windows PowerShell **5.1 x64** first, then PowerShell **7.5+ x64**. The runner fails closed for incomplete, skipped, empty or failed suites and disables Pester's unused HKCU TestRegistry fixture. A fresh process is required for each selection below.

```powershell
.\tests\Invoke-Tests.ps1 -Path @(
  '.\tests\Invoke-Tests.Tests.ps1', '.\tests\runtime.Tests.ps1',
  '.\tests\runtime-bootstrap.Tests.ps1', '.\tests\runtime-native.Tests.ps1',
  '.\tests\runtime-cancel-reset.Tests.ps1', '.\tests\hpcc4-simple.Tests.ps1',
  '.\tests\completion.Tests.ps1', '.\tests\tools-gpo.Tests.ps1',
  '.\tests\companions.Tests.ps1'
) -ResultDirectory .\results\ordinary
# Separate fresh x64 processes:
.\tests\Invoke-Tests.ps1 -Path .\tests\runtime-native-child.Tests.ps1 -ResultDirectory .\results\native-child
.\tests\Invoke-Tests.ps1 -Path .\tests\runtime-compile.Tests.ps1 -ResultDirectory .\results\compiler
```

Never use broad directory discovery on this repository: it mixes the compiler and child graphs. Explicitly launch the selected engine with `-NoProfile -NonInteractive -ExecutionPolicy Bypass`; this is a process-local override. CI uses the same three selections.

Production definitions are pinned and their load AST/guard is checked before tests enter them. Refresh pins only after reviewing changed source and reachable mocked/default-denied leaves. Fixtures use independently verified TestDrive paths with provider/reparse/containment checks; real I/O stays within those bounds. Host-changing natives, ACLs, accounts, registry, services, installers, history/log clearing and deferred deletion remain denied. Module-qualified cmdlet calls can still be intercepted by Pester: fixture reads use guarded CLR I/O to avoid recursive mocks.

The harmless-child suite permits only the selected engine and reviewed inert child bodies, plus an invalid-source reset refusal. The compiler suite compiles actual identity/deferred-removal literals within TestDrive and never invokes their host APIs. Mock success establishes control flow and contracts; live Server enforcement/acceptance remains separate.

The workspace's external original tests were preserved. The repository main suite was migrated from stale name/native-sidecar assumptions to actual SID, effective-policy, committed-record and cleanup interfaces; runtime suites retain the recovered common-mechanics regressions.
