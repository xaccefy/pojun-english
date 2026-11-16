package hosttools

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInventoryCoversCatalog(t *testing.T) {
	inv := Inventory()
	// The number of catalog entries changes as tools are added, so this only asserts
	// "not below the baseline" and checks field completeness per entry.
	if len(inv) < 22 {
		t.Fatalf("catalog should have at least 22 entries, got %d", len(inv))
	}
	// curl should exist in any test environment (Git/CI images ship it); use it to verify
	// that probing really works
	foundCurl := false
	for _, t2 := range inv {
		if t2.Bin == "" {
			t.Errorf("%s: Bin was not filled in", t2.Name)
		}
		if t2.Name == "curl" {
			foundCurl = true
			if !t2.Available {
				t.Error("curl should be detected as available")
			}
			if t2.Install != "" {
				t.Error("an available tool should carry no install hint")
			}
		}
	}
	if !foundCurl {
		t.Fatal("curl is not in the catalog")
	}
}

func TestSummaryShape(t *testing.T) {
	s := Summary()
	avail, ok := s["available"].([]string)
	if !ok || len(avail) == 0 {
		t.Fatalf("available should be a non-empty string array: %#v", s["available"])
	}
	// missing only carries names: install hints are for humans (the host environment
	// page); the model cannot install anything and does not need to know how, so
	// handing it dozens of install commands just burns context every turn.
	missing, ok := s["missing"].([]string)
	if !ok {
		t.Fatalf("wrong type for missing: %#v", s["missing"])
	}
	for _, m := range missing {
		if m == "" {
			t.Error("a missing entry should not be an empty string")
		}
	}
	// Every available entry must carry its purpose: with names only the model picks the
	// wrong tool.
	for _, a := range avail {
		if !strings.Contains(a, ": ") {
			t.Errorf("available entry %q should carry a purpose", a)
		}
	}
	if s["hint"] == "" {
		t.Fatal("hint must not be empty")
	}
}

func TestSummaryTextMarksAvailability(t *testing.T) {
	// Use a temporary PATH containing only an empty directory so every tool is missing
	// (environment-independent)
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	txt := SummaryText()
	// PATH-based tools are necessarily missing under an empty PATH; but tools detected
	// via python:module (kombu/pymysql/redis) go through python3 -c import and are
	// unaffected by PATH — they show as available whenever the module is installed.
	// So only assert that PATH-based tools do not appear (matched by name) rather than
	// requiring the whole string to be empty.
	for _, name := range []string{"curl", "nmap"} {
		if strings.Contains(txt, "✓ "+name+" ") || strings.Contains(txt, "✓ "+name+"\n") {
			t.Errorf("PATH-based tool %s should not appear under an empty PATH: %s", name, txt)
		}
	}
	// When tools are present the purpose must be attached — with names only the model
	// cannot tell which one fits which situation.
	dir2 := t.TempDir()
	fake := dir2 + string(os.PathSeparator) + "curl"
	if runtime.GOOS == "windows" {
		fake += ".exe"
	}
	if err := os.WriteFile(fake, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir2)
	txt2 := SummaryText()
	if !strings.Contains(txt2, "curl") {
		t.Errorf("curl should be listed when tools are present: %s", txt2)
	}
	if !strings.Contains(txt2, "HTTP") {
		t.Errorf("available entries should carry a purpose: %s", txt2)
	}
	if strings.Contains(txt2, "nmap") {
		t.Errorf("missing tools should not appear in the list: %s", txt2)
	}
	// Put a fake curl on PATH; it should flip to available (on Windows LookPath only
	// accepts executable extensions such as .exe)
	name := "curl"
	if runtime.GOOS == "windows" {
		name = "curl.exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	txt = SummaryText()
	if !containsAll(txt, "✓ curl") {
		t.Errorf("the fake curl should be marked available: %s", txt)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
