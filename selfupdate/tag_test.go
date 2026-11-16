package selfupdate

import "testing"

// The two spellings of a version (with/without v) must convert into each other — the
// Release tag is v0.3.23 while the version injected into the binary is 0.3.23, and the
// helper gets a 404 looking it up the latter way.
func TestAlternateTag(t *testing.T) {
	cases := map[string]string{
		"v0.3.23": "0.3.23",
		"0.3.23":  "v0.3.23",
		"v1.0.0":  "1.0.0",
		"1.0.0":   "v1.0.0",
	}
	for in, want := range cases {
		if got := alternateTag(in); got != want {
			t.Errorf("alternateTag(%q)=%q, want %q", in, got, want)
		}
	}
}

// ValidVersionTag is the only input validation for hostd /self-upgrade; it must block
// tricks.
func TestValidVersionTag(t *testing.T) {
	ok := []string{"0.3.23", "v0.3.23", "1.0.0"}
	for _, s := range ok {
		if !ValidVersionTag(s) {
			t.Errorf("%q should be accepted", s)
		}
	}
	bad := []string{"", "latest", "0.3", "0.3.23.4", "../etc/passwd", "0.3.23;id", "v0.3.23\n"}
	for _, s := range bad {
		if ValidVersionTag(s) {
			t.Errorf("%q should be rejected", s)
		}
	}
}
