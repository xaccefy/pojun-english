package db

import (
	"errors"
	"fmt"
)

// Built-in task templates (v0.4.60, the PentestAgent Playbook idea): turn validated task goal structures
// (internal workflow breakdown + boundary discipline -- the Ankang-series task goals use this format and measured as the best output)
// into preset playbooks that can be applied in one click when creating a task, instead of a blank goal.
//
// The seed policy is the same as intercept rules: a settings flag records the batch, once inserted it is skipped, and later user
// deletions/modifications are never resurrected. intercept_rules is left empty -- a playbook only owns the goal structure; operating constraints come from scope.

type builtinTaskPlaybook struct {
	name        string
	description string
	goal        string
}

var builtinTaskPlaybooks = []builtinTaskPlaybook{
	{
		name:        "Playbook: Full-lifecycle web penetration (hospital/government & enterprise sites)",
		description: "Applies to: a web system on one or a few domains (authorized site + named entry points). Five serial stages: asset discovery → unauthenticated-surface probing → business-flow testing → verification and evidence → report. The template measured on the Ankang-series tasks (the goal structure that produced 295 findings).",
		goal: `Run a complete pentest against the authorized target "{{target name}}" and produce a reproducible vulnerability report. **One target set, advanced strictly serially by dependency: asset discovery → service identification → vulnerability probing → verification → report. No skipped steps, no repeated scanning.**

[Authorization scope]
- Authorization type: user-authorized pentest (execute per the scope description in the task description; assets outside scope are only recorded for attribution verification, not tested).
- Named entry points: the URLs/hosts given in the task description are authoritative and all must be tested.
- IP assets: only include services whose ownership by the target entity can be proven by certificate/registration/ASN; business on the same IP/subnet that clearly belongs to a third party must not be tested further.

[Internal workflow (serial, plan the breakdown yourself)]
1. Asset discovery and identification: DNS/subdomains/certificate transparency/port and service identification/HTTP fingerprinting/directory and endpoint discovery/front-end JS hardcoded endpoints and keys (SPA sites must run js_audit to check for sourcemap leaks);
2. Unauthenticated-surface vulnerability probing: information disclosure (.git/.env/backups/Swagger/Actuator/phpinfo/directory traversal/source leaks), unauthenticated access, missing authorization, CORS configuration, error message disclosure, known component CVEs (confirm the fingerprint before verifying);
3. Business-flow testing: login/reset/rebind flows, payment/coupon/points logic, IDOR and mass assignment -- verify only up to "can read someone else's data" and stop; bulk extraction of business data is forbidden;
4. Verification and evidence: give a minimal reproducible request and response for each vulnerability (curl command + key output); for HTTP vulnerabilities keep the real traffic ID and bind it; grade severity strictly by evidence (only L3 reports high/critical, L2 is medium at most);
5. Report: register each finding and write a detailed report (overview/impact/reproduction steps/evidence/remediation advice), then output the asset inventory, finding list (ordered by risk) and remediation priority.

[Boundaries]
- Production environments are read-only/minimal verification; do not break availability, do not delete or modify business data, do not bulk register;
- Stop at a proof for sensitive data; if there is no response or a strong WAF blocks it, record it and move to the next target instead of hammering repeatedly.`,
	},
	{
		name:        "Playbook: Internal AD domain penetration (pivot into the domain after gaining a foothold)",
		description: "Applies to: an external foothold or in-domain reachability already exists (VPN/office network). Flow: stabilize the foothold → local privilege escalation → credential collection → lateral movement → domain-specific techniques (Kerberoast/DCSync/ADCS) → data access proof. Evidence at every step; only pivot into subnets whose ownership has been proven.",
		goal: `Run an Active Directory penetration test starting from internal reachability and produce an attack-path report. **Serial progression: foothold → privilege escalation → credentials → lateral movement → domain-specific techniques → data access proof; land the facts at each step before moving on.**

[Authorization scope]
- The internal subnets/pivot hosts given in the task description are the boundary; do not pivot to hosts whose ownership is not proven.

[Internal workflow]
1. Foothold stabilization and information gathering: identity/privileges/network position/defensive surface (EDR/AV/egress restrictions), landing an initial-access fact;
2. Local privilege escalation: sudo -l/SUID/cron jobs/service config (Linux), whoami /priv/unquoted paths/stored credentials (Windows) → search_vulns for kernel/component privilege-escalation CVEs;
3. Credential collection: config files/SSH private keys/shell history/LSASS/SAM/DPAPI/GPP -- write credentials in full into a fact (no abbreviation, no masking) and verify usability group by group;
4. Lateral movement: direct SSH/RDP/SMB/WinRM with credentials → impacket family (psexec/wmiexec/secretsdump) → tunnels (chisel/ligolo) → converging scans of proven subnets;
5. Domain-specific techniques: domain enumeration → Kerberoast/AS-REP → delegation → ADCS (certipy find -vulnerable) → DCSync (requires privileges; export only the minimum set);
6. Data access proof: read-only minimal samples of target data, save_evidence for proof, bind the traffic.

[Boundaries]
- No write operations on domain controllers or production hosts; check the lockout policy before credential spraying and try at most 2-3 times;
- Persistence is only a feasibility demonstration (landed as a fact), never actually deployed;
- Blocked by EDR/policy → record the blocking shape and preconditions instead of hammering repeatedly.`,
	},
	{
		name:        "Playbook: APP reverse engineering + API penetration",
		description: "Applies to: the target is a mobile APP (APK/IPA) and its backend API. Flow: static analysis to extract endpoints and keys → dynamic capture to fill gaps → API broken-access-control/injection testing → client vulnerability verification (exported components/WebView/certificate pinning) → report.",
		goal: `Run a mobile penetration test against "{{APP name and backend API}}" and produce a vulnerability report. **Core idea: reverse engineering gets you the keys, the server side is the real battlefield.**

[Authorization scope]
- The APP itself and the backend domains listed in the description; reverse engineering is only used to discover endpoints and credentials, and server-side testing only hits authorized domains.

[Internal workflow]
1. Static analysis: apktool/jadx decompilation → extract every endpoint, baseURL, signing algorithm, hardcoded AK/SK/token (landed in full as a fact) → exported component/deep-link inventory;
2. Dynamic gap filling: capture traffic through a proxy (bypass SSL verification only on your own test build) → reconcile static endpoints against real traffic;
3. API penetration: call the backend directly with the recovered signing algorithm → broken access control (swap id/swap token)/unauthenticated access/injection/logic (following the api-security-testing flow) → keep a minimal sample as evidence for each;
4. Client verification: exported-component launch-argument injection, WebView injection, allowBackup export, missing certificate verification (demonstrated on your own build);
5. Report: register endpoint leaks/hardcoded credentials/unauthorized data reads/exposed components one by one, with reverse-engineering evidence and endpoint reproduction.

[Boundaries]
- Do not reverse engineer or test APPs outside the authorization; do not bypass payment or copyright protection for non-testing purposes;
- For endpoints involving user privacy, prove that one record is readable and do not bulk extract.`,
	},
	{
		name:        "Playbook: Recon only - asset inventory (no exploitation)",
		description: "Applies to: asset inventory and attack-surface stocktaking only (e.g. the customer just wants an asset list), or the first phase of a broad authorization. Output: asset inventory + fingerprints + attack-surface risk list, with no exploitation verification.",
		goal: `Complete an asset inventory for "{{target domain/IP range}}" and produce an asset inventory and attack-surface risk list. **This task is recon only, no exploitation**: no vulnerability exploitation, no brute forcing, no directory brute forcing -- only existence and fingerprint confirmation.

[Internal workflow]
1. Ownership verification: registration/certificates/whois/ASN, recording ownership evidence item by item;
2. Asset discovery: subdomain enumeration (passive first)/port and service identification/HTTP fingerprinting -- http_probe for bulk liveness checks;
3. Attack-surface annotation: exposed admin consoles, debug endpoints (Swagger/Actuator/Druid), outdated component versions, default pages, anonymously accessible services -- record only "exists + fingerprint", do not go deeper;
4. Ingestion: insert_assets for every asset and attribute them to the company; give an attack-surface risk summary per category.

[Output]
- Asset inventory (domain/IP/port/service/fingerprint); attack-surface risk list (ordered by risk, with evidence screenshots); list of items with doubtful ownership (recorded, not tested).`,
	},
}

// seedBuiltinTaskPlaybooks seeds the built-in task templates (the PentestAgent Playbook idea, implemented).
// The settings flag records the batch; once inserted it is skipped -- later user deletions/modifications are never resurrected.

func (d *DB) seedBuiltinTaskPlaybooks() error {
	const flag = "task_playbooks_v1"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	for _, pb := range builtinTaskPlaybooks {
		in := TaskTemplateInput{
			Name:        pb.name,
			Description: pb.description,
			Goal:        pb.goal,
		}
		if _, err := d.CreateTaskTemplate(in); err != nil {
			// A template with the same name already exists = skip (the user may have edited the content; the seed never overwrites); anything else is returned as-is.

			if errors.Is(err, ErrTaskTemplateNameConflict) {
				continue
			}
			return fmt.Errorf("playbook %q: %w", pb.name, err)
		}
	}
	return d.SetSetting(flag, "done")
}
