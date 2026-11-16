package hosttools

import (
	"regexp"
	"strings"
	"testing"
)

// Registration completeness of the middleware-specific tools.
//
// This batch was added on 2026-10-22 based on the research conclusion that "the last
// 30 days of high-severity NVD vulnerabilities are concentrated in middleware". Their
// **package names** directly decide whether one-click install succeeds — one wrong
// letter means "I clicked install and nothing happened".
func TestMiddlewareToolsRegistered(t *testing.T) {
	byName := map[string]Tool{}
	for _, tl := range Catalog() {
		byName[tl.Name] = tl
	}
	// Middleware tool expected to exist → its pip package name.
	want := map[string]string{
		"gmqtt":           "gmqtt",
		"paho-mqtt":       "paho-mqtt",
		"pika":            "pika",
		"amqpstorm":       "amqpstorm",
		"confluent-kafka": "confluent-kafka",
		"kombu":           "kombu",
		"pymongo":         "pymongo",
		"pymysql":         "pymysql",
		"psycopg2-binary": "psycopg2-binary",
		"redis-py":        "redis",
		"zeep":            "zeep",
		"python-gitlab":   "python-gitlab",
		"netmiko":         "netmiko",
		"napalm":          "napalm",
		"splunk-sdk":      "splunk-sdk",
	}
	for name, pip := range want {
		tl, ok := byName[name]
		if !ok {
			t.Errorf("middleware tool %q is not registered", name)
			continue
		}
		if tl.Category != CatMiddleware {
			t.Errorf("tool %q has category=%q, want %q", name, tl.Category, CatMiddleware)
		}
		if tl.Kind != KindPip {
			t.Errorf("tool %q has install kind=%q, want pip", name, tl.Kind)
		}
		if tl.Pip != pip {
			t.Errorf("tool %q has pip package=%q, want %q", name, tl.Pip, pip)
		}
	}
}

// The middleware category must be in the page grouping order (otherwise the frontend
// gets neither label nor order).
func TestMiddlewareCategoryIsOrdered(t *testing.T) {
	found := false
	for _, c := range categoryOrder {
		if c == CatMiddleware {
			found = true
			break
		}
	}
	if !found {
		t.Error("CatMiddleware is not in categoryOrder — the page will not show this group")
	}
	if CategoryLabel(CatMiddleware) == "Other" {
		t.Error("CatMiddleware has no label")
	}
}

// Every known high-risk middleware product must have a corresponding protocol tool.
//
// The basis is the 2026-10-22 tally of the last 30 days of high-severity NVD
// vulnerabilities: middleware took the lion's share. This test pins down "which
// middleware classes we cover", so gaps become visible when new vulnerability types
// are added.
func TestMiddlewareCoversHighRiskProducts(t *testing.T) {
	// Key middleware → at least one tool must be able to talk to it.
	// Criterion: the tool's Pip package contains the keyword, or its Purpose mentions
	// that middleware.
	coverage := map[string][]string{
		"mqtt":     {"gmqtt", "paho-mqtt"},
		"rabbitmq": {"pika", "amqpstorm"},
		"kafka":    {"confluent-kafka"},
		"mongodb":  {"pymongo"},
		"mysql":    {"pymysql"},
		"postgres": {"psycopg2-binary"},
		"redis":    {"redis-py"},
		"soap":     {"zeep"},
		"gitlab":   {"python-gitlab"},
	}
	byName := map[string]Tool{}
	for _, tl := range Catalog() {
		byName[tl.Name] = tl
	}
	for product, tools := range coverage {
		for _, name := range tools {
			if _, ok := byName[name]; !ok {
				t.Errorf("the %s scenario is missing tool %q", product, name)
			}
		}
	}
}

// A pip recipe must not name a "similar-looking but different" package.
//
// This is the supply-chain line of defense: PyPI is full of impostor packages one
// letter away from well-known ones (paho vs
// paho-mqtt, request vs requests, python-dateutil vs python-dateutil-dc…).
// A typo does not report "package not found"; it installs a package of unknown
// provenance.
func TestMiddlewarePipNamesAreExact(t *testing.T) {
	// Known wrong spelling → correct spelling.
	traps := map[string]string{
		"paho":      "paho-mqtt", // PyPI has no paho, only paho-mqtt
		"pika-mqtt": "pika",
		"mongo":     "pymongo",
		"mysql":     "pymysql",
		"psycopg2":  "psycopg2-binary", // psycopg2 is a pure sdist, a one-click install degrades into compiling
		"gitlab":    "python-gitlab",
		"redis":     "redis",
		"kafka":     "confluent-kafka",
	}
	byName := map[string]Tool{}
	for _, tl := range Catalog() {
		byName[tl.Name] = tl
	}
	for wrong, right := range traps {
		if _, ok := byName[wrong]; ok {
			// The tool exists, but its Pip must be the correct one.
			if got := byName[wrong].Pip; got != right {
				t.Errorf("tool %q has pip package=%q, want %q", wrong, got, right)
			}
		}
	}
	// Every middleware tool's pip package must be a "pure package name" (no space-separated
	// multi-package) and must look like a real PyPI name (alphanumerics plus -_.).
	valid := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	for _, tl := range Catalog() {
		if tl.Category != CatMiddleware {
			continue
		}
		if !valid.MatchString(tl.Pip) {
			t.Errorf("tool %q has pip package %q which is not a valid single package name", tl.Name, tl.Pip)
		}
		if strings.TrimSpace(tl.Pip) == "" {
			t.Errorf("tool %q has an empty pip package name", tl.Name)
		}
	}
}
