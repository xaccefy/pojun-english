package server

import (
	"strings"
	"testing"
)

// Up-front validation of the DB CHECK constraints. Regression background: a contract
// audit found POST /api/llm/profiles and POST /api/mcp returning 500 + SQLSTATE 23514 on
// illegal format/transport (raw DB constraint errors surfacing to users), and POST
// /api/llm/profiles/active returning 500 for a missing profile. All three should be 4xx
// so callers can fix the request instead of seeing 'internal server error'.

func TestCheckEnumRejectsInvalidValues(t *testing.T) {
	if msg := checkEnum("format", "openai", validLLMProfileFormats); msg != "" {
		t.Fatalf("valid format rejected: %s", msg)
	}
	if msg := checkEnum("format", "gemini", validLLMProfileFormats); msg == "" {
		t.Fatal("invalid format accepted")
	} else if !strings.Contains(msg, "format") || !strings.Contains(msg, "gemini") {
		t.Fatalf("error message should name the field and the value: %s", msg)
	}
	if msg := checkEnum("format", "", validLLMProfileFormats); msg == "" {
		t.Fatal("empty format accepted")
	}
	if msg := checkEnum("transport", "sse", validMCPTransports); msg != "" {
		t.Fatalf("valid transport rejected: %s", msg)
	}
	if msg := checkEnum("transport", "grpc", validMCPTransports); msg == "" {
		t.Fatal("invalid transport accepted")
	}
}

// The allowed-value sets must match db/schema.sql's CHECKs, else up-front validation
// lets through values the DB still rejects (back to 500).
func TestValidSetsMatchSchemaConstraints(t *testing.T) {
	for _, f := range []string{"openai", "anthropic", "openai-responses"} {
		if !validLLMProfileFormats[f] {
			t.Errorf("format %q must be accepted (schema CHECK allows it)", f)
		}
	}
	if len(validLLMProfileFormats) != 3 {
		t.Errorf("format set size = %d, want 3", len(validLLMProfileFormats))
	}
	for _, tr := range []string{"stdio", "http", "sse"} {
		if !validMCPTransports[tr] {
			t.Errorf("transport %q must be accepted (schema CHECK allows it)", tr)
		}
	}
	if len(validMCPTransports) != 3 {
		t.Errorf("transport set size = %d, want 3", len(validMCPTransports))
	}
}
