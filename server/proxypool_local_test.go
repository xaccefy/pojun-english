package server

import (
	"testing"

	"github.com/chu0119/pojun/traffic"
)

func TestParseLocalPorts(t *testing.T) {
	got := parseLocalPorts("7897, 7897, abc, 0, 70000, 1080")
	if len(got) != 2 || got[0] != 7897 || got[1] != 1080 {
		t.Fatalf("parseLocalPorts=%v，期望 [7897 1080]", got)
	}
	if got := parseLocalPorts(""); len(got) == 0 {
		t.Fatal("空设置应回退默认端口")
	}
}

func TestAddLocalCandidates(t *testing.T) {
	st := &proxyPoolState{Entries: []traffic.PoolEntry{
		{URL: "http://127.0.0.1:7897", Name: "my-clash", Enabled: false, Weight: 2},
	}}
	cands := []localProxyCandidate{
		{URL: "http://127.0.0.1:7897", Port: 7897, OK: true},
		{URL: "http://127.0.0.1:7890", Port: 7890, OK: false},
		{URL: "http://127.0.0.1:1080", Port: 1080, OK: true},
	}
	added := addLocalCandidates(st, cands, "")
	if added != 2 {
		t.Fatalf("added=%d，期望 2（启用已有 + 新增）", added)
	}
	if len(st.Entries) != 2 {
		t.Fatalf("entries=%d，期望 2", len(st.Entries))
	}
	if !st.Entries[0].Enabled || st.Entries[0].Name != "my-clash" || st.Entries[0].Weight != 2 {
		t.Fatalf("已有条目被覆盖: %+v", st.Entries[0])
	}
	if st.Entries[1].Name != "local-clash-1080" || !st.Entries[1].Enabled {
		t.Fatalf("新增条目异常: %+v", st.Entries[1])
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "localhost", "::1"} {
		if !isLoopbackHost(h) {
			t.Fatalf("%s 应判定为回环", h)
		}
	}
	for _, h := range []string{"10.0.0.1", "example.com", ""} {
		if isLoopbackHost(h) {
			t.Fatalf("%s 不应判定为回环", h)
		}
	}
}
