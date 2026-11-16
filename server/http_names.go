package server

import (
	"net/url"
	"strings"
)

// attachmentDisposition builds a Content-Disposition header that old clients can parse
// while carrying CJK names correctly. filename= holds an ASCII fallback (non-ASCII
// replaced with _); the original name goes in RFC 5987's filename* (UTF-8 percent-
// encoded) so download names don't render as mojibake.
func attachmentDisposition(name string) string {
	if name == "" {
		name = "download"
	}
	ascii := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	if ascii == "" || ascii == "_" {
		ascii = "download"
	}
	if ascii == name {
		return `attachment; filename="` + ascii + `"`
	}
	return `attachment; filename="` + ascii + `"; filename*=UTF-8''` + url.PathEscape(name)
}
