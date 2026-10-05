---
name: gpo-verify
description: Read-only verification of the actual selected GPO package and operator expectations, with Unknown and NotConfigured distinct from failures or false values.
---

Read the repository's `gpo-verification-checklist.md` and the actual operator-approved package expectations. Run only the listed read-only configuration observations on the authorized target. Do not evaluate arbitrary Markdown as a script, refresh/import policy, or change configuration.

Report setting, source, expected value from the selected package/operator, observed value and status. A missing value is NotConfigured; an access/query failure is Unknown. If no package expectation is supplied, report the observation without inventing PASS/FAIL. Never infer RID500 rename/enablement or local firewall merge behavior from a package name/GUID. Effective ActiveStore profiles and all rule filters matter; mock/import success does not prove connectivity.
