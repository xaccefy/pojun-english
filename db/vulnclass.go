package db

// Canonical enum and normalization for vulnerability classes (vulnclass).
// Background: the vulnclass a model reports is free text, so the same class shows up under a dozen
// different spellings (SQLi / sql_injection / ...), diluting both the aggregate view and fingerprint dedup with synonyms.
// Here we define a stable allowlist + alias normalization table, folding variants into the canonical class at the
// write layer (RecordFindingTx/add_goal); input outside the allowlist keeps its original value (no information destroyed) and aggregates naturally on equal values.

import "strings"

// VulnClassList is the canonical class allowlist (used by prompts to steer the model; the order is the report display order).
var VulnClassList = []string{
	"Injection",
	"XSS",
	"Unauthorized Access",
	"Weak Password",
	"Arbitrary File Upload",
	"Arbitrary File Read",
	"Deserialization",
	"RCE",
	"SSRF",
	"XXE",
	"Information Disclosure",
	"Privilege Escalation",
	"Authentication Bypass",
	"Logical Vulnerability",
	"Denial of Service",
	"MITM",
	"Known Vulnerability",
	"Misconfiguration",
	"Other",
}

var vulnClassAliases = map[string]string{
	"sqli": "Injection", "sqlinjection": "Injection", "sqlinject": "Injection",
	"commandinjection": "Injection", "ldapinjection": "Injection",
	"templateinjection": "Injection", "ssti": "Injection", "injection": "Injection", "nosqlinjection": "Injection",
	"xpathinjection": "Injection", "injectionvulnerability": "Injection", "promptinjection": "Injection",
	"cmdinjection": "Injection",
	// XSS
	"xss": "XSS", "crosssitescripting": "XSS", "storedxss": "XSS", "reflectedxss": "XSS",
	"domxss": "XSS",
	"idor":   "Unauthorized Access", "unauthorizedprivilegeescalation": "Unauthorized Access", "horizontalprivilegeescalation": "Unauthorized Access", "verticalprivilegeescalation": "Unauthorized Access",
	"unauthorized": "Unauthorized Access", "unauthorizedaccessattempt": "Unauthorized Access", "unauthorizedaccess": "Unauthorized Access",
	"brokenaccesscontrol": "Unauthorized Access", "accesscontrol": "Unauthorized Access", "permissionbypass": "Unauthorized Access",
	"weakpassword": "Weak Password", "defaultcredentials": "Weak Password",
	"defaultpassword": "Weak Password", "passwordbruteforce": "Weak Password", "bruteforce": "Weak Password",
	"fileupload": "Arbitrary File Upload", "arbitraryfileuploadvulnerability": "Arbitrary File Upload", "unrestrictedfileupload": "Arbitrary File Upload",
	"uploadvulnerability": "Arbitrary File Upload", "webshell": "Arbitrary File Upload",
	"lfi": "Arbitrary File Read", "pathtraversal": "Arbitrary File Read", "directorytraversal": "Arbitrary File Read",
	"arbitraryfiledownload": "Arbitrary File Read", "arbitraryfileinclusion": "Arbitrary File Read", "fileinclusion": "Arbitrary File Read",
	"fileread": "Arbitrary File Read", "localfileinclusion": "Arbitrary File Read",
	"deserialization": "Deserialization", "deserializationvulnerability": "Deserialization", "javadeserialization": "Deserialization",
	"insecuredeserialization": "Deserialization",
	// RCE
	"rce": "RCE", "remotecodeexecution": "RCE", "remotecommandexecution": "RCE",
	"commandexecution": "RCE", "codeexecution": "RCE", "commandinjectionvulnerability": "RCE", "oscommandinjection": "RCE",
	// SSRF
	"ssrf": "SSRF", "serversiderequestforgery": "SSRF",
	// XXE
	"xxe": "XXE", "xmlexternalentity": "XXE", "xmlentityinjection": "XXE",
	"informationdisclosure": "Information Disclosure", "sensitiveinformationdisclosure": "Information Disclosure", "informationleakage": "Information Disclosure",
	"sourcecodedisclosure": "Information Disclosure", "backupfile": "Information Disclosure", "directorylisting": "Information Disclosure",
	"stacktracedisclosure": "Information Disclosure", "debuginformationdisclosure": "Information Disclosure", "disclosure": "Information Disclosure",
	"privilegeescalation": "Privilege Escalation", "privesc": "Privilege Escalation",
	"localprivilegeescalation": "Privilege Escalation", "privilegeescalationvulnerability": "Privilege Escalation",
	"authbypass": "Authentication Bypass", "authenticationbypass": "Authentication Bypass", "loginbypass": "Authentication Bypass",
	"signinbypass": "Authentication Bypass", "identityauthenticationbypass": "Authentication Bypass",
	"businesslogic": "Logical Vulnerability", "paymentlogic": "Logical Vulnerability",
	"captchabypass": "Logical Vulnerability", "logicalflaw": "Logical Vulnerability", "replayattack": "Logical Vulnerability", "racecondition": "Logical Vulnerability",
	"dos": "Denial of Service", "ddos": "Denial of Service", "denialofservice": "Denial of Service", "slowattack": "Denial of Service",
	"mitm": "MITM", "maninthemiddleattack": "MITM", "plaintexttransmission": "MITM", "weakencryption": "MITM",
	"certificateissue": "MITM", "httpsdowngrade": "MITM", "arpspoofing": "MITM",
	"cve": "Known Vulnerability", "nday": "Known Vulnerability", "knownvulnerability": "Known Vulnerability",
	"eternalblue": "Known Vulnerability", "historicalvulnerability": "Known Vulnerability", "componentvulnerability": "Known Vulnerability",
	"misconfiguration": "Misconfiguration", "wrongconfiguration": "Misconfiguration", "cors": "Misconfiguration",
	"securityconfiguration": "Misconfiguration", "serviceconfiguration": "Misconfiguration",
	"other": "Other", "uncategorized": "Other", "unknown": "Other",
}

// NormalizeVulnClass normalizes a reported vulnerability class to the canonical enum:
// case/whitespace/hyphen insensitive; an alias-table hit -> canonical class; a miss -> keep the original TrimSpace value.
// An empty string is still empty after normalization (upstream validation requires it).
func NormalizeVulnClass(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	key := strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(s))
	if v, ok := vulnClassAliases[key]; ok {
		return v
	}
	// A CVE/MS id written as the class -> known vulnerability (the id belongs in name, but do not destroy this input's classification)
	if strings.HasPrefix(key, "cve") || strings.HasPrefix(key, "ms") && isDigits(key[2:]) {
		return "Known Vulnerability"
	}
	// An allowlist member itself (including case variants such as "xss" or "RCE") maps straight to the canonical spelling
	for _, c := range VulnClassList {
		if strings.EqualFold(c, s) {
			return c
		}
	}
	return s
}

// VulnClassPromptText is the allowlist text used by prompts (referenced from schema descriptions; single source).
func VulnClassPromptText() string {
	return strings.Join(VulnClassList, "/")
}

// isDigits reports whether the string is all digits (used for CVE/MS id prefix normalization).

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
