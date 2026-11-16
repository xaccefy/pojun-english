package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Repo is the release source.
//
// Deliberately a build-time variable rather than a **runtime config option**: a
// configurable update source is a remote-code-execution channel for anyone who can edit
// the config, and a pentest platform cannot afford that hole. Forks/mirrors must
// override it at build time with
// `-ldflags "-X github.com/chu0119/pojun/selfupdate.Repo=owner/name"`, so what changes
// is the artifact itself rather than a switch that can be tampered with at runtime.
var Repo = "chu0119/pojun"

func latestURL() string { return "https://api.github.com/repos/" + Repo + "/releases/latest" }

func tagURL(tag string) string {
	return "https://api.github.com/repos/" + Repo + "/releases/tags/" + tag
}

// allowedHosts restricts the domains the upgrade chain may reach. Together with
// checkRedirect below, any hop redirected to a host outside the list fails outright —
// this is the first gate against DNS poisoning / a man in the middle swapping the
// binary; the second is the SHA256SUMS comparison.
var allowedHosts = map[string]bool{
	"api.github.com":                       true,
	"github.com":                           true,
	"objects.githubusercontent.com":        true, // object storage the release assets actually land on
	"release-assets.githubusercontent.com": true,
	"raw.githubusercontent.com":            true,
}

// Release holds the GitHub Release fields we care about.
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Assets      []Asset   `json:"assets"`
}

// Asset is a file attached to a Release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// NewClient builds an HTTP client that only trusts GitHub domains. An empty proxy means
// a direct connection.
//
// The default Transport is deliberately not reused: the upgrade chain must force TLS
// and verify certificates, and must not be affected by an InsecureSkipVerify or similar
// set elsewhere.
func NewClient(proxy string) *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if p := strings.TrimSpace(proxy); p != "" {
		if pu, err := url.Parse(p); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Minute, // downloads the whole bundle, so a per-request timeout would kill it
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return checkURL(req.URL)
		},
	}
}

// checkURL enforces https + the domain whitelist.
func checkURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("refusing a non-HTTPS address: %s", u.Scheme+"://"+u.Host)
	}
	if !allowedHosts[strings.ToLower(u.Hostname())] {
		return fmt.Errorf("refusing a non-GitHub domain: %s", u.Hostname())
	}
	return nil
}

// FetchLatest queries the latest stable release.
func FetchLatest(ctx context.Context, c *http.Client) (*Release, error) {
	return fetchRelease(ctx, c, latestURL(), "latest stable release")
}

// FetchByTag queries the Release for a given tag (used when the companion binary
// replaces itself aligned to the main program's version).
//
// Version numbers come in two forms: the Release tag carries a v prefix (v0.3.23) while
// the version injected into the binary does not (build.sh strips it with
// `${POJUN_BUILD_VERSION#v}`). Both are tried so a formatting difference does not
// report "version not found" — hostd hit exactly this when looking up 0.3.23.
func FetchByTag(ctx context.Context, c *http.Client, tag string) (*Release, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return nil, fmt.Errorf("missing version number")
	}
	rel, err := fetchRelease(ctx, c, tagURL(tag), tag)
	if err == nil {
		return rel, nil
	}
	if rel2, err2 := fetchRelease(ctx, c, tagURL(alternateTag(tag)), tag); err2 == nil {
		return rel2, nil
	}
	return nil, err
}

// alternateTag returns the other spelling of the same version (v0.3.23 ↔ 0.3.23).
func alternateTag(tag string) string {
	if strings.HasPrefix(tag, "v") {
		return strings.TrimPrefix(tag, "v")
	}
	return "v" + tag
}

func fetchRelease(ctx context.Context, c *http.Client, apiURL, what string) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if err := checkURL(req.URL); err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "pojun-selfupdate")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach GitHub (a global proxy can be configured in system settings): %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusTooManyRequests:
		// The unauthenticated GitHub API allows 60 requests per hour per IP; sharing an
		// egress IP hits that easily.
		return nil, fmt.Errorf("GitHub API rate limited (60 requests per hour), please try again later")
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("repository %s has no %s", Repo, what)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GitHub returned %d", resp.StatusCode)
	}

	var rel Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("failed to parse the release: %w", err)
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return nil, fmt.Errorf("release has no tag")
	}
	return &rel, nil
}

// AssetName returns the bundle name for the current platform, matching build.sh's
// package_binary: pojun-<version>-<os>-<arch>.zip (the version carries no v prefix).
func AssetName(tag, goos, goarch string) string {
	return fmt.Sprintf("pojun-%s-%s-%s.zip", strings.TrimPrefix(tag, "v"), goos, goarch)
}

// FindAsset finds an asset in the Release by name.
func (r *Release) FindAsset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return Asset{}, false
}
