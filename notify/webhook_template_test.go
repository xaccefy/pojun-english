package notify

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// This file pins the generic webhook template's **capability boundary**.
//
// It's the only place in the package where a user-supplied string is evaluated as code,
// so what it can and cannot do must be explicit — and pinned by tests. Otherwise someone
// will casually add a method to the template context or a readFile to the FuncMap, the
// capability surface silently grows, and the diff looks like a harmless little function.

// TestTemplateContextHasNoMethods is the most important one.
//
// text/template invokes exported methods ({{.Foo}} reads a field or calls a method). So
// if the template context can reach **any** type with exported methods, those methods are
// exposed to the template author. This feature's context is deliberately pure data
// (exported fields only, zero methods).
//
// If this fails: someone added methods to webhookTemplateData / webhookItem. Before
// allowing it, think hard about whether a template could use that method to read
// something not meant to be exposed.
func TestTemplateContextHasNoMethods(t *testing.T) {
	for _, v := range []any{webhookTemplateData{}, webhookItem{}} {
		typ := reflect.TypeOf(v)
		if n := typ.NumMethod(); n != 0 {
			var names []string
			for i := 0; i < n; i++ {
				names = append(names, typ.Method(i).Name)
			}
			t.Fatalf("%s exposes %d methods (%s): text/template can call them, "+
				"which hands those capabilities to the template author", typ.Name(), n, strings.Join(names, ", "))
		}
	}
}

// TestTemplateFuncsAreMinimal pins the function set exposed to templates.
//
// Every FuncMap entry is one more capability. Currently only json / jsons — they
// serialize values into JSON fragments. No file reads, no requests, no commands.
func TestTemplateFuncsAreMinimal(t *testing.T) {
	var got []string
	for name := range webhookTemplateFuncs {
		got = append(got, name)
	}
	sort.Strings(got)
	want := []string{"json", "jsons"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("template func set changed: got %v, want %v. Before adding a function, confirm it doesn't widen the capability surface"+
			" (no file I/O, no network requests, no command execution)", got, want)
	}
}

// TestTemplateCannotReachUnknownData covers out-of-bounds template access:
// touching something nonexistent must fail — not echo anything back — and the failure
// must not carry internal data.
func TestTemplateCannotReachUnknownData(t *testing.T) {
	_, err := renderWebhookBody(`{"x": {{.Environment}}, "y": {{.Env}}}`, singleMsg())
	if err == nil {
		t.Fatal("accessing a nonexistent field should error")
	}
	// the error must not contain real template-context content (vuln title/summary).
	for _, leak := range []string{"SQL injection", "parameter id"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("template error leaks message content %q: %v", leak, err)
		}
	}
}

// TestTemplateRenderFailsPermanently: a bad template is a config error — retries don't
// heal it. If classified retryable, one bad template makes every delivery waste three
// backoff rounds.
func TestTemplateRenderFailsPermanently(t *testing.T) {
	cfg := map[string]any{
		"url":           "https://example.com/hook",
		"body_template": `{{.Items.`,
	}
	if err := (webhookChannel{}).Validate(cfg); err == nil {
		t.Fatal("template syntax errors should be rejected at save")
	}
	// even bypassing validation straight to delivery must still classify permanent — not retry.
	_, err := (webhookChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("a bad template should classify permanent, got %v", err)
	}
}

// TestTemplateCanOnlyProduceJSON covers the 'rendered template must be valid JSON'
// constraint. It also blocks 'use the template to emit plain text that drives another
// protocol' shenanigans.
func TestTemplateCanOnlyProduceJSON(t *testing.T) {
	// a valid template passes.
	ok := map[string]any{"url": "https://example.com/hook", "body_template": `{"t":{{json .Title}}}`}
	if err := (webhookChannel{}).Validate(ok); err != nil {
		t.Fatalf("a valid template should pass validation: %v", err)
	}
	// non-JSON output must be rejected (not sent verbatim).
	bad := map[string]any{"url": "http://127.0.0.1:1/hook", "body_template": `not json {{.Count}}`}
	_, err := (webhookChannel{}).Send(context.Background(), bad, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("non-JSON output should classify permanent, got %v", err)
	}
	if !strings.Contains(err.Error(), "valid JSON") {
		t.Errorf("error should indicate a JSON problem, got %v", err)
	}
}
