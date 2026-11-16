package vulnintel

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

// KevEntry is one record of the CISA Known Exploited Vulnerabilities catalog.
type KevEntry struct {
	CVEID         string
	Vendor        string
	Product       string
	DateAdded     time.Time
	Description   string
	RansomwareUse string
}

// KevCatalog is the parsed feed (also carries catalogVersion for the watermark).
type KevCatalog struct {
	Version         string
	DateReleased    time.Time
	Count           int
	Vulnerabilities []KevEntry
}

// FetchKEV downloads and parses the KEV JSON feed. Full-catalog semantics: the
// file is small (~2k entries) and replaced wholesale daily, so there is no
// incremental cursor — every sync overwrites the kev flags it can match.
func (c *NvdClient) FetchKEV(ctx context.Context) (*KevCatalog, error) {
	// KEV lives on cisa.gov and has nothing to do with NVD's Base. This used to build the URL
	// from c.Base, and NewNvdClient sets Base to services.nvd.nist.gov, so every run requested
	// https://services.nvd.nist.gov/sites/default/files/feeds/... and got back a 404 XHTML
	// error page — KEV sync never once succeeded and the database held no in-the-wild flag at
	// all. Tests override Base (httptest), so Base still wins and cisa.gov is the default.
	base := c.Base
	if base == "" || base == "https://services.nvd.nist.gov" {
		base = "https://www.cisa.gov"
	}
	// KEV lives on cisa.gov regardless of the NVD base override; only tests swap it.
	feedURL := base + "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	if _, err := url.Parse(feedURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("kev feed status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var raw struct {
		CatalogVersion  string `json:"catalogVersion"`
		DateReleased    string `json:"dateReleased"`
		Count           int    `json:"count"`
		Vulnerabilities []struct {
			CVEID              string `json:"cveID"`
			VendorProject      string `json:"vendorProject"`
			Product            string `json:"product"`
			DateAdded          string `json:"dateAdded"`
			ShortDescription   string `json:"shortDescription"`
			KnownRansomwareUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("kev feed decode: %w", err)
	}
	cat := &KevCatalog{Version: raw.CatalogVersion, Count: raw.Count}
	if t, e := time.Parse("2006-01-02", strings.TrimSpace(raw.DateReleased)); e == nil {
		cat.DateReleased = t
	}
	for _, v := range raw.Vulnerabilities {
		if v.CVEID == "" {
			continue
		}
		e := KevEntry{
			CVEID:         strings.TrimSpace(v.CVEID),
			Vendor:        strings.TrimSpace(v.VendorProject),
			Product:       strings.TrimSpace(v.Product),
			Description:   strings.TrimSpace(v.ShortDescription),
			RansomwareUse: strings.TrimSpace(v.KnownRansomwareUse),
		}
		// KEV dates are "2024-01-02" (date only).
		if t, perr := time.Parse("2006-01-02", strings.TrimSpace(v.DateAdded)); perr == nil {
			e.DateAdded = t
		}
		cat.Vulnerabilities = append(cat.Vulnerabilities, e)
	}
	return cat, nil
}
