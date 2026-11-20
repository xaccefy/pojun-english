package hostd

import (
	"strings"
	"testing"

	"github.com/chu0119/pojun/hosttools"
)

// Release asset naming is very inconsistent across projects (architecture first or last,
// version with or without v, extension .zip/.tar.gz/.gz, and four architecture naming
// sets: amd64/x86_64/x86/x64). A wrong template means one-click install gets a 404 while
// the user only sees "install failed".
//
// The expected values here are the real asset names measured against the GitHub API in
// 2026-10.
func TestAssetURLMatchesRealReleaseNames(t *testing.T) {
	cases := []struct {
		id   string
		tag  string
		want string
	}{
		{
			"nuclei", "v3.4.10",
			"https://github.com/projectdiscovery/nuclei/releases/download/v3.4.10/nuclei_3.4.10_linux_amd64.zip",
		},
		{
			"gitleaks", "v8.30.1",
			"https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
		},
		{
			"chisel", "v1.12.0",
			"https://github.com/jpillora/chisel/releases/download/v1.12.0/chisel_1.12.0_linux_amd64.gz",
		},
		{
			// amass asset names carry no version
			"amass", "v5.1.1",
			"https://github.com/OWASP/Amass/releases/download/v5.1.1/amass_linux_amd64.tar.gz",
		},
		{
			// dalfox has a v prefix and uses x86_64 for the architecture
			"dalfox", "v3.2.4",
			"https://github.com/hahwul/dalfox/releases/download/v3.2.4/dalfox-v3.2.4-linux-x86_64.tar.gz",
		},
		{
			// feroxbuster puts the architecture first
			"feroxbuster", "v2.13.1",
			"https://github.com/epi052/feroxbuster/releases/download/v2.13.1/x86_64-linux-feroxbuster.zip",
		},
		{
			"notify", "v1.0.7",
			"https://github.com/projectdiscovery/notify/releases/download/v1.0.7/notify_1.0.7_linux_amd64.zip",
		},
		{
			"interactsh-client", "v1.4.1",
			"https://github.com/projectdiscovery/interactsh/releases/download/v1.4.1/interactsh-client_1.4.1_linux_amd64.zip",
		},
	}
	for _, c := range cases {
		tool, ok := hosttools.Lookup(c.id)
		if !ok {
			t.Errorf("%s is not in the catalog", c.id)
			continue
		}
		tmpl := strings.Split(tool.AssetTmpl, "||")[0] // 多候选取首候选验证
		got := GitHubAssetURL(tool, tmpl, c.tag)
		if got != c.want {
			t.Errorf("%s URL is wrong:\n  got  %s\n  want %s", c.id, got, c.want)
		}
	}
}

// Templates must not contain unimplemented placeholders — they would be spliced in as a
// literal "{archX}" and the download would necessarily 404.
func TestNoUnknownPlaceholdersInTemplates(t *testing.T) {
	known := map[string]bool{
		"{ver}": true, "{verv}": true,
		"{arch}": true, "{arch2}": true, "{arch3}": true, "{arch4}": true, "{arch5}": true,
	}
	for _, tool := range hosttools.Catalog() {
		if tool.Kind != hosttools.KindGitHub {
			continue
		}
		for _, seg := range strings.Split(tool.AssetTmpl, "{")[1:] {
			end := strings.Index(seg, "}")
			if end < 0 {
				t.Errorf("template %q of %s has an unclosed placeholder", tool.AssetTmpl, tool.Name)
				continue
			}
			ph := "{" + seg[:end] + "}"
			if !known[ph] {
				t.Errorf("template %q of %s uses unknown placeholder %s", tool.AssetTmpl, tool.Name, ph)
			}
		}
	}
}

// Every GitHub recipe must have a Repo and an asset template, or it cannot install.
func TestGitHubRecipesAreComplete(t *testing.T) {
	for _, tool := range hosttools.Catalog() {
		if tool.Kind != hosttools.KindGitHub {
			continue
		}
		if tool.Repo == "" {
			t.Errorf("%s is missing Repo", tool.Name)
		}
		if tool.AssetTmpl == "" {
			t.Errorf("%s is missing AssetTmpl", tool.Name)
		}
		if tool.Bin == "" {
			t.Errorf("%s is missing Bin", tool.Name)
		}
	}
}
