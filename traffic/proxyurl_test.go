package traffic

import "testing"

// The bulk-import entry point is ValidateProxyURL: url.Parse barely errors on space-free
// garbage such as "http://badline-not-an-address" (it treats it as a path), so gibberish
// would be accepted as a valid proxy. This test guards that line of defense.
func TestValidateProxyURLRejectsGarbage(t *testing.T) {
	bad := []string{
		"http://badlîne-this-is-not-an-address",
		"http://has space",
		"not-a-url",
		"ftp://1.2.3.4:21",
		"http://",
		"http://1.2.3.4:abc",
	}
	for _, raw := range bad {
		if _, err := ValidateProxyURL(raw); err == nil {
			t.Errorf("ValidateProxyURL(%q) should error", raw)
		}
	}
	good := []string{
		"http://1.2.3.4:8080",
		"https://proxy.example.com:3128",
		"socks5://user:pass@5.6.7.8:1080",
		"http://a:1", // single-label host name: common on intranets, must not be rejected
		"http://[::1]:8080",
	}
	for _, raw := range good {
		if _, err := ValidateProxyURL(raw); err != nil {
			t.Errorf("ValidateProxyURL(%q) should not error: %v", raw, err)
		}
	}
}
