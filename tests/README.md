Run the fixture-only suite with Pester **5.9.1** installed in the engine's module path:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Invoke-Tests.ps1
pwsh.exe -NoProfile -NonInteractive -File .\tests\Invoke-Tests.ps1
```

Windows PowerShell 5.1 is primary and PowerShell 7 is secondary. The runner never installs modules. It returns process success only for a nonempty, fully passing suite with no failed containers/blocks, skipped, not-run or inconclusive tests. Optional `-Path` selects a suite; `-ResultDirectory` writes a sanitized count/runtime summary. Dot-source the runner to call `Invoke-Hpcc4Tests` without exiting the caller. The previous `HPCC4_PESTER_RUNNING` flag, scalar global exit state and process TLS are restored in `finally`, including infrastructure errors. Caller preferences are unchanged.

Production is only dot-sourced. Mutating account/firewall/service/download/archive/process/registry/history/native commands have throwing defaults and deliberate per-test mocks. Fixture writes use TestDrive; Pester owns TestRegistry infrastructure. Literal appcmd, LGPO, Sysmon and .NET log clearing remain unreachable. Cleanup mocks history inputs/removal and returns empty log enumeration. The only real native production status probes select inbox System32 cmd.exe with fixed `/d /c exit N` arguments. Runner child probes use the current PowerShell engine and harmless TestDrive suites. No production hardening entry point runs against the host.

The current cleanup policy explicitly refuses directory self-deletion, including existing external paths; unresolved paths fail closed with a manual-removal diagnostic. Exact-file deletion is deferred. Passing these mocks establishes the tested calls, state and refusal behavior; it does not establish effective firewall, ACL, GPO, Sysmon or server behavior.
