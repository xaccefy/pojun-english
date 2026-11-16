package vulnintel

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// FetchKEV must hit cisa.gov, not NVD's Base.
//
// In production, every sync cycle emitted "kev feed status 404" plus an XHTML error page: the URL was
// assembled as
// https://services.nvd.nist.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
// (a curl against the same path indeed returned a 404 XHTML page). KEV therefore never synced successfully.
//
// Here we feed the production client's default Base unchanged and only replace the Transport to observe the actual requested address.
func TestFetchKEVUsesCisaHostNotNvdBase(t *testing.T) {
	var requested []string
	prod := &NvdClient{
		Base: "https://services.nvd.nist.gov", // this is what NewNvdClient sets
		HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			requested = append(requested, r.URL.Scheme+"://"+r.URL.Host+r.URL.Path)
			return nil, context.Canceled // only care about the address, no need to actually complete
		})},
	}
	_, _ = prod.FetchKEV(context.Background())

	if len(requested) != 1 {
		t.Fatalf("expected exactly one request, got %v", requested)
	}
	if !strings.HasPrefix(requested[0], "https://www.cisa.gov/") {
		t.Fatalf("KEV must hit cisa.gov, got %s", requested[0])
	}
	if !strings.HasSuffix(requested[0], "/sites/default/files/feeds/known_exploited_vulnerabilities.json") {
		t.Fatalf("unexpected KEV path: %s", requested[0])
	}
}
