package agent

import (
	"encoding/json"
	"strings"
)

// Intent dimension (v0.7.0): deterministic dedupe for 'same asset × same technique, zero yield'.
// The planner may set dimension explicitly or it gets inferred from summary — both normalize here.
const (
	dimRecon      = "recon"
	dimAuthz      = "authz"
	dimInjection  = "injection"
	dimUpload     = "upload"
	dimSSRF       = "ssrf"
	dimRCE        = "rce"
	dimCredReuse  = "cred-reuse"
	dimDataExport = "data-export"
	dimPayment    = "payment"
	dimPrivesc    = "privesc"
	dimLateral    = "lateral"
)

var dimensionAliases = map[string]string{
	"recon": "recon", "reconnaissance": "recon", "reconnaissance sweep": "recon", "information gathering": "recon",
	"authz": "authz", "authorization": "authz", "idor": "authz", "unauthorized access": "authz", "permissions": "authz",
	"injection": "injection", "sqli": "injection", "xss": "injection", "ssti": "injection", "injection flaw": "injection",
	"upload": "upload", "uploading": "upload", "file upload": "upload",
	"ssrf": "ssrf", "ssrf-probe": "ssrf",
	"rce": "rce", "command": "rce", "exec": "rce", "command execution": "rce", "code execution": "rce",
	"cred-reuse": "cred-reuse", "cred": "cred-reuse", "credential": "cred-reuse", "credentials": "cred-reuse", "password reuse": "cred-reuse",
	"data-export": "data-export", "data": "data-export", "export": "data-export", "data extraction": "data-export", "data export": "data-export",
	"payment": "payment", "pay": "payment", "payments": "payment", "funds": "payment", "orders": "payment",
	"privesc": "privesc", "privilege": "privesc", "privilege escalation": "privesc",
	"lateral": "lateral", "lateral movement": "lateral",
}

// dimensionInferRules match summary, highest priority first.
var dimensionInferRules = []struct {
	dim string
	kws []string
}{
	{dimPayment, []string{"payments", "price change", "callback", "settlement", "funds", "refund", "payment", "checkout", "order status"}},
	{dimCredReuse, []string{"credentials", "passphrase", "password", "reuse", "ak/sk", "accesskey", "token", "credential", "login as"}},
	{dimPrivesc, []string{"privilege escalation", "root", "sudo", "suid", "system permissions", "privesc"}},
	{dimLateral, []string{"lateral movement", "intranet", "jump host", "lateral", "pivot"}},
	{dimUpload, []string{"uploading", "upload", "file inclusion", "parsing"}},
	{dimRCE, []string{"command execution", "code execution", "rce", "getshell", "webshell", "deserialization", "template injection", "ssti"}},
	{dimSSRF, []string{"ssrf", "cloud metadata", "metadata", "internal probing", "callback"}},
	{dimInjection, []string{"injection flaw", "sqli", "sql", "xss", "privilege-abuse parameter", "injection"}},
	{dimDataExport, []string{"data extraction", "exporting", "bulk data", "unauthorized read", "data plane", "export", "dump"}},
	{dimAuthz, []string{"privilege abuse", "idor", "permission bypass", "unauthorized access", "authz"}},
	{dimRecon, []string{"reconnaissance sweep", "enumeration", "scanning", "fingerprinting", "directories", "subdomains", "ports", "recon"}},
}

func normalizeDimension(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if d, ok := dimensionAliases[s]; ok {
		return d
	}
	// Compound values like "authz/post-login-privesc" are allowed: take the first recognizable token.
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == ',' || r == '|' || r == ' ' }) {
		if d, ok := dimensionAliases[strings.TrimSpace(part)]; ok {
			return d
		}
	}
	return ""
}

func inferDimension(text string) string {
	low := strings.ToLower(text)
	for _, rule := range dimensionInferRules {
		for _, kw := range rule.kws {
			if strings.Contains(low, kw) {
				return rule.dim
			}
		}
	}
	return ""
}

// intentDimension returns the intent's final dimension: explicit value wins, else inferred from summary.
func intentDimension(explicit, summary string) string {
	if d := normalizeDimension(explicit); d != "" {
		return d
	}
	return inferDimension(summary)
}

// IsExploitDimension says whether the dimension is 'exploit/deep-dive' class: these intents often need
// dozens of consecutive requests and multi-step chains (grab creds → login → privesc → pull data) — the lease wall clock needs loosening.
func IsExploitDimension(dim string) bool {
	switch dim {
	case dimInjection, dimUpload, dimSSRF, dimRCE, dimCredReuse, dimDataExport, dimPayment, dimPrivesc, dimLateral:
		return true
	}
	return false
}

// ExploitDimensionFromPayload reads dimension/summary from an intent node payload (JSON) and classifies.
// Returns false when the payload won't parse (conservative: no loosening).
func ExploitDimensionFromPayload(payload json.RawMessage) bool {
	if len(payload) == 0 {
		return false
	}
	var m map[string]any
	if json.Unmarshal(payload, &m) != nil {
		return false
	}
	explicit, _ := m["dimension"].(string)
	summary, _ := m["summary"].(string)
	if summary == "" {
		summary, _ = m["title"].(string)
	}
	return IsExploitDimension(intentDimension(explicit, summary))
}
