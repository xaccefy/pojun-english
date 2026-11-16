package server

import (
	"fmt"
	"sort"
	"strings"
)

// Up-front validation mirroring the DB CHECK constraints.
//
// Why validate before the database errors: a constraint violation surfaces as 500 +
// SQLSTATE 23514 — the frontend shows 'internal server error' instead of 'your format
// value is wrong'. The contract tests exposed this directly: POST /api/llm/profiles and
// POST /api/mcp returned 5xx on empty params, while 4xx is the answer a caller can act
// on.
//
// Allowed values must stay in sync with the CHECKs in db/schema.sql:
//   llm_profiles_format_check     CHECK (format IN ('openai','anthropic','openai-responses'))
//   mcp_servers_transport_check   CHECK (transport IN ('stdio','http','sse'))

// validLLMProfileFormats matches llm_profiles_format_check.
var validLLMProfileFormats = map[string]bool{
	"openai":           true,
	"anthropic":        true,
	"openai-responses": true,
}

// validMCPTransports matches mcp_servers_transport_check.
var validMCPTransports = map[string]bool{
	"stdio": true,
	"http":  true,
	"sse":   true,
}

// checkEnum returns "" on pass, else a user-displayable reason.
func checkEnum(field, value string, allowed map[string]bool) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return fmt.Sprintf("%s must not be empty", field)
	}
	if !allowed[v] {
		keys := make([]string, 0, len(allowed))
		for k := range allowed {
			keys = append(keys, k)
		}
		// fixed order so the error message stays identical across calls.
		sort.Strings(keys)
		return fmt.Sprintf("%s has an invalid value: %q — allowed: %s", field, value, strings.Join(keys, ", "))
	}
	return ""
}
