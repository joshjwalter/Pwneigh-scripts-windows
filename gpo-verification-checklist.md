# DoD STIG GPO verification checklist

Settings **removed from `hpcc4-simple.ps1`** because the DoD STIG GPO applies them.
After running the GPO (`Install-DodGpo`), confirm each one actually took. Run every
`Verify` line elevated; the listed value is what STIG expects.

---

## 1. RDP Network Level Authentication
- **Script used to set:** `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication = 1`
- **GPO sets (policy key):** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication = 1`
- **Verify:**
  ```powershell
  (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name UserAuthentication -EA SilentlyContinue).UserAuthentication
  ```
  Expect `1`. (Policy key wins over the old Control key, so also check nothing left the Control key at 0.)

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
- **GPO does:** *renames* the built-in Administrator (`[System Access] NewAdministratorName`) but leaves it **enabled** for recovery. The STIG does NOT disable it.
- **Consequence:** if you specifically wanted the built-in Admin disabled, the GPO will NOT do that. Decide whether renamed+enabled is acceptable; if you still want it disabled, do it by hand after verifying another admin works.
- **Verify:**
  ```powershell
  Get-LocalUser | Where-Object { ($_.SID.Value -split '-')[-1] -eq 500 } | Select-Object Name, Enabled
  ```

---

## Still in the script on purpose (overlaps the GPO but NOT removed)

- **Firewall** (`Set-FirewallLockdown` / `Open-ServicePorts`) — kept, because it also does competition-specific work the GPO can't: keeps the live RDP port open during the run, opens your scored-service ports at the end, and warns on uncovered listeners. The STIG firewall GPO also enforces profile state/default-block. **Watch for a conflict:** if the STIG sets `AllowLocalPolicyMerge = 0`, your local `HPCC4-Keep-*` allow rules are ignored. `Install-DodGpo` now checks this itself right after `gpupdate /force` and logs a `WARNING` if it finds it set (it also warns if the GPO turned on RDP NLA) — but that's a best-effort runtime check, not a substitute for the manual verify below. Check:
  ```powershell
  LGPO.exe /parse /m "<GUID>\DomainSysvol\GPO\Machine\registry.pol" | Select-String "WindowsFirewall","AllowLocalPolicyMerge"
  ```
- **Local passwords** (`Set-LocalPasswords`) — kept, because the GPO sets password *policy* (length/complexity/history/age), not the actual passwords. You still must change compromised/default passwords and submit them. Just make sure the passwords you choose satisfy the STIG policy or later changes will be rejected.
- **Unauthorized account deletion** (`Remove-UnauthorizedUsers`) — kept, the GPO can't know which accounts are red-team backdoors.
