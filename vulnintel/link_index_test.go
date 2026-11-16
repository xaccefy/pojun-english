package vulnintel

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

// cveRowLite is the minimal CVE row used by the equivalence tests (only CVEID and Product needed).
type cveRowLite struct {
	CVEID   string
	Product string
}

// matchLegacy is the pre-refactor matching algorithm: O(asset × tech × product) triple nesting.
// It is kept as a "reference implementation" — the new algorithm must produce the same hit set.
func matchLegacy(assets [][]string, cves []cveRowLite) map[int][]string {
	byProduct := map[string][]cveRowLite{}
	for _, c := range cves {
		byProduct[c.Product] = append(byProduct[c.Product], c)
	}
	out := map[int][]string{}
	for i, techs := range assets {
		var hit []cveRowLite
		for _, tech := range techs {
			toks := techTokens(tech)
			if len(toks) == 0 {
				continue
			}
			for product, cs := range byProduct {
				pts := cpeTokens(product)
				for _, pt := range pts {
					for _, tok := range toks {
						if tok == pt {
							hit = append(hit, cs...)
							break
						}
					}
				}
			}
		}
		for _, c := range hit {
			out[i] = append(out[i], c.CVEID)
		}
	}
	return out
}

// matchIndexed is the post-refactor algorithm: a token inverted index.
func matchIndexed(assets [][]string, cves []cveRowLite) map[int][]string {
	tokIndex := map[string][]cveRowLite{}
	for _, c := range cves {
		for _, pt := range cpeTokens(c.Product) {
			tokIndex[pt] = append(tokIndex[pt], c)
		}
	}
	out := map[int][]string{}
	for i, techs := range assets {
		var hit []cveRowLite
		seen := map[string]bool{}
		for _, tech := range techs {
			for _, tok := range techTokens(tech) {
				for _, c := range tokIndex[tok] {
					if seen[c.CVEID] {
						continue
					}
					seen[c.CVEID] = true
					hit = append(hit, c)
				}
			}
		}
		for _, c := range hit {
			out[i] = append(out[i], c.CVEID)
		}
	}
	return out
}

func normHits(m map[int][]string) map[int][]string {
	out := map[int][]string{}
	for k, v := range m {
		s := append([]string{}, v...)
		sort.Strings(s)
		// Deduplicate: the old implementation might append the same CVE multiple times (same product hit by multiple tokens)
		dedup := s[:0]
		for i, x := range s {
			if i == 0 || x != s[i-1] {
				dedup = append(dedup, x)
			}
		}
		out[k] = dedup
	}
	return out
}

// The refactor (inverted index) must not change matching results. Run equivalence assertions with random data + a real vocabulary.
func TestIndexedMatchEqualsLegacy(t *testing.T) {
	techs := []string{
		"Apache httpd 2.4.49", "nginx", "OpenSSH", "MySQL 5.7",
		"Microsoft Windows Server 2008 R2", "Huawei AirEngine",
		"PostgreSQL 14", "redis", "Tomcat", "httpd", "http_server",
		"IIS", "VMware ESXi", "unknown-thing", "",
	}
	products := []string{
		"http_server", "apache_tomcat", "nginx", "openssh", "mysql",
		"microsoft_windows_server_2008", "ubuntu_linux", "windows_server_2008",
		"tomcat", "postgresql", "redis", "vmware_esxi", "office_excel_viewer",
		"openview_network_node_manager", "acrobat",
	}

	rng := rand.New(rand.NewSource(20261020))
	for round := 0; round < 40; round++ {
		nAsset := 1 + rng.Intn(6)
		nCVE := 1 + rng.Intn(8)
		var assets [][]string
		for i := 0; i < nAsset; i++ {
			var ts []string
			for j := 0; j < 1+rng.Intn(3); j++ {
				ts = append(ts, techs[rng.Intn(len(techs))])
			}
			assets = append(assets, ts)
		}
		var cves []cveRowLite
		for i := 0; i < nCVE; i++ {
			cves = append(cves, cveRowLite{
				CVEID:   fmt.Sprintf("CVE-2024-%05d", i),
				Product: products[rng.Intn(len(products))],
			})
		}
		got := normHits(matchIndexed(assets, cves))
		want := normHits(matchLegacy(assets, cves))
		if len(got) != len(want) {
			t.Fatalf("round %d: different number of matched assets got=%d want=%d", round, len(got), len(want))
		}
		for k, wv := range want {
			gv, ok := got[k]
			if !ok {
				t.Fatalf("round %d: asset %d old algorithm hit %v, new algorithm did not", round, k, wv)
			}
			if len(gv) != len(wv) {
				t.Fatalf("round %d: asset %d different hit count got=%v want=%v", round, k, gv, wv)
			}
			for i := range wv {
				if gv[i] != wv[i] {
					t.Fatalf("round %d: asset %d different hit set got=%v want=%v", round, k, gv, wv)
				}
			}
		}
	}
}

// The inverted index must correctly handle the duplicate hits of "one product with multiple
// cpeTokens": when the same CVE hits the same asset through multiple tokens, it should appear only once.
func TestIndexedMatchDedupsWithinAsset(t *testing.T) {
	// cpeTokens for "http_server" includes forms such as http_server / httserver / httpd,
	// and techTokens("http_server") also produces multiple forms → it inevitably hits the same CVE through multiple routes.
	assets := [][]string{{"http_server"}}
	cves := []cveRowLite{{CVEID: "CVE-2024-00001", Product: "http_server"}}
	got := matchIndexed(assets, cves)
	if ids := got[0]; len(ids) != 1 {
		t.Fatalf("the same CVE should appear only once, got %v", ids)
	}
}

// Deduplication must not cross assets: two assets hitting the same CVE are two separate things.
func TestIndexedMatchKeepsSameCVEAcrossAssets(t *testing.T) {
	assets := [][]string{{"nginx"}, {"nginx"}}
	cves := []cveRowLite{{CVEID: "CVE-2024-00001", Product: "nginx"}}
	got := matchIndexed(assets, cves)
	if len(got) != 2 {
		t.Fatalf("both assets should hit, actually hit %d assets", len(got))
	}
	for k, ids := range got {
		if len(ids) != 1 || ids[0] != "CVE-2024-00001" {
			t.Fatalf("asset %d hit anomaly: %v", k, ids)
		}
	}
}
