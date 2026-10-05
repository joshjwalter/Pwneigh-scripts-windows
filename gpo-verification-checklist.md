# Selected-package policy verification

The main script imports only operator-selected, ordered manifests. No setting is assumed because a folder is called STIG or because LGPO returned zero. Obtain expected values, names and enablement from the actual approved package, target OS/role and competition packet.

Read-only checks on the target:

```powershell
Get-NetFirewallProfile -PolicyStore ActiveStore |
    Select-Object Name, Enabled, DefaultInboundAction, AllowLocalFirewallRules
Get-NetFirewallRule -PolicyStore ActiveStore |
    Where-Object Name -like 'HPCC4-*' |
    Select-Object Name, Enabled, Direction, Action, Profile, PolicyStoreSourceType
Get-NetFirewallRule -PolicyStore ActiveStore |
    Where-Object Name -like 'HPCC4-*' | Get-NetFirewallPortFilter
Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name UserAuthentication -ErrorAction Stop
Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication,PortNumber -ErrorAction Stop
Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction Stop
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Get-LocalUser | Where-Object { ([string]$_.SID -split '-')[-1] -in '500','501' } | Select-Object Name,SID,Enabled
```

Missing values are **NotConfigured**; failed/access-denied reads are **Unknown**, distinct from false. Record the actual value and its source next to the package/operator expectation. Do not infer built-in Administrator rename/enablement policy: verify the selected package and retained operator access explicitly.

`AllowLocalFirewallRules` from ActiveStore is the relevant effective observation. A raw policy key or successful import is insufficient proof of rule merge, filters, RDP connectivity or scored-service reachability. Inspect address/application/service/interface/security filters as well as ports. Do not enable local merge automatically to bypass domain policy.

These commands only observe configuration. Do not run `gpupdate`, import policies, set registry values, disable accounts or change firewall settings as part of verification. Actual packet/RDP/DHCP and selected-package acceptance must be checked in the authorized Server environment; ordinary CI uses mocks.
