# DoD STIG GPO verification checklist

Settings **removed from `hpcc4-simple.ps1`** because the DoD STIG GPO applies them.
After running the GPO (`Install-DodGpo`), confirm each one actually took. Run every
`Verify` line elevated; the listed value is what STIG expects. §1 and §7 are the exceptions:
NLA is set by the script, and FIPS is deliberately left off by the bundle.

---

## 1. RDP Network Level Authentication — set by the SCRIPT, not the GPO
- **No GPO in the DISA package sets NLA**, so the script sets it again (`Set-RdpNla`):
  `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication = 1`
- **Verify:**
  ```powershell
  (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication
  (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name UserAuthentication -EA SilentlyContinue).UserAuthentication
  ```
  Expect `1`, then `1` or nothing. A policy value of `0` would override the first one.

## 2. WDigest credential caching disabled
- **Script used to set:** `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0`
- **GPO sets:** same key = 0
- **Verify:**
  ```powershell
  (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -EA SilentlyContinue).UseLogonCredential
  ```
  Expect `0`.

## 3. SMBv1 disabled
- **Script used to set:** `Set-SmbServerConfiguration -EnableSMB1Protocol $false`
- **GPO sets:** removes/disables the SMB1 feature + `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 = 0`
- **Verify:**
  ```powershell
  (Get-SmbServerConfiguration).EnableSMB1Protocol      # expect False
  (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State   # expect Disabled/DisabledWithPayloadRemoved
  ```

## 4. SMB signing required (server)
- **Script used to set:** `Set-SmbServerConfiguration -RequireSecuritySignature $true`
- **GPO sets:** `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature = 1`
- **Verify:**
  ```powershell
  (Get-SmbServerConfiguration).RequireSecuritySignature   # expect True
  ```

## 5. Built-in Guest account disabled
- **Script used to do:** disable the RID-501 account
- **GPO sets:** `[System Access] EnableGuestAccount = 0` (and STIG renames it)
- **Verify:**
  ```powershell
  Get-LocalUser | Where-Object { ($_.SID.Value -split '-')[-1] -eq 501 } | Select-Object Name, Enabled
  ```
  Expect `Enabled = False`.

## 6. Built-in Administrator  — NOTE: GPO behaves DIFFERENTLY
- **Script used to (optionally) do:** *disable* the RID-500 account (`$DisableBuiltinAdmin`)
- **GPO does:** *renames* the built-in Administrator (`[System Access] NewAdministratorName`) but leaves it **enabled** for recovery. The STIG does NOT disable it. The bundle uses **your own name** (`build-gpo-bundle.ps1 -AdminName`, recorded in the bundle's `CHANGES.md`), not DISA's `X_Admin`. `Install-DodGpo` prints the new name right after applying.
- **Consequence:** from then on, log in with the new name. If you specifically wanted the built-in Admin disabled, the GPO will NOT do that; do it by hand after verifying another admin works.
- **Verify:**
  ```powershell
  Get-LocalUser | Where-Object { ($_.SID.Value -split '-')[-1] -eq 500 } | Select-Object Name, Enabled
  ```
  Expect your `-AdminName`, `Enabled = True`.

## 7. FIPS mode stays OFF
- **Bundle removes** the STIG's `FIPSAlgorithmPolicy\Enabled = 1` (breaks older web apps and RDP/SSH clients).
- **Verify:**
  ```powershell
  (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy' -Name Enabled -EA SilentlyContinue).Enabled
  ```
  Expect `0` or nothing.

---

## Still in the script on purpose (overlaps the GPO but NOT removed)

- **Firewall** (`Set-FirewallLockdown` / `Open-ServicePorts`) — kept, because it also does competition-specific work the GPO can't: keeps the live RDP port open during the run, opens your scored-service ports at the end, and warns on uncovered listeners. The STIG firewall GPO also enforces profile state/default-block. **Watch for a conflict:** if the STIG sets `AllowLocalPolicyMerge = 0`, your local `HPCC4-Keep-*` allow rules are ignored. `Install-DodGpo` now checks this itself right after `gpupdate /force` and logs a `WARNING` if it finds it set — but that's a best-effort runtime check, not a substitute for the manual verify below. Check:
  ```powershell
  LGPO.exe /parse /m "<GUID>\DomainSysvol\GPO\Machine\registry.pol" | Select-String "WindowsFirewall","AllowLocalPolicyMerge"
  ```
- **Outbound default-block** (`Set-OutboundLockdown`) — this one goes *against* the STIG on purpose. The DoD firewall STIG requires outbound **allow** by default, and a policy setting beats the local one, so the firewall STIG GPO would silently undo the outbound lockdown. That's why `build-gpo-bundle.ps1` leaves it out (and strips the firewall policy from the 2012 R2 baseline). `Install-DodGpo` still logs a `WARNING` if it sees `DefaultOutboundAction = 0` in policy. Check:
  ```powershell
  Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, DefaultOutboundAction   # want Block
  ```
- **Local passwords** (`Set-LocalPasswords`) — kept, because the GPO sets password *policy* (length/complexity/history/age), not the actual passwords. You still must change compromised/default passwords and submit them. Just make sure the passwords you choose satisfy the STIG policy or later changes will be rejected.
- **Unauthorized account deletion** (`Remove-UnauthorizedUsers`) — kept, the GPO can't know which accounts are red-team backdoors.
