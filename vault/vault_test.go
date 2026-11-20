package vault

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chu0119/pojun/db"
)

func TestEncryptDecryptAndMask(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain := "P@ssw0rd-中文-$`\""
	enc, err := s.encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(enc), plain) {
		t.Fatal("密文里出现了明文")
	}
	got, err := s.decrypt(enc)
	if err != nil || got != plain {
		t.Fatalf("解密失败: %q %v", got, err)
	}
	if _, err := s.decrypt(enc[:10]); err == nil {
		t.Fatal("截断密文应解密失败")
	}
	if m := maskSecret(plain); strings.Contains(m, "P@ss") || !strings.HasSuffix(m, "`\"") {
		t.Fatalf("掩码泄漏过多: %q", m)
	}
	if maskSecret("abc") != "****" {
		t.Fatal("短口令应整体掩码")
	}
}

func TestKeyPersistedAndReused(t *testing.T) {
	dir := t.TempDir()
	s1, err := Open(dir, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.key")); err != nil {
		t.Fatalf("主密钥未落盘: %v", err)
	}
	s2, err := Open(dir, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := s1.encrypt("hello")
	if got, err := s2.decrypt(enc); err != nil || got != "hello" {
		t.Fatalf("重启后无法用同一主密钥解密: %q %v", got, err)
	}
}

func TestNormalizeKindPrivilege(t *testing.T) {
	cases := map[string]string{"pass": "password", "JWT": "token", "ssh": "key", "": "password"}
	for in, want := range cases {
		if got := normalizeKind(in); got != want {
			t.Fatalf("kind %q → %q，期望 %q", in, got, want)
		}
	}
	if normalizePrivilege("Administrator") != "admin" || normalizePrivilege("SYSTEM") != "root" {
		t.Fatal("权限级别归一失败")
	}
}

// taskID=0 的 ToolSet 只能读全局条目；taskID<0 才是管理端全量。
func TestGetTaskIsolation(t *testing.T) {
	dsn := os.Getenv("POJUN_PG_DSN")
	if dsn == "" {
		t.Skip("POJUN_PG_DSN 未设置")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s, err := Open(dir, dir, pg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id1, err := s.Save(ctx, SaveInput{TaskID: 101, Kind: "password", Username: "a", Secret: "s1"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := s.Save(ctx, SaveInput{TaskID: 202, Kind: "password", Username: "b", Secret: "s2"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if it, err := s.Get(ctx, id1, 202); err != nil || it != nil {
		t.Fatalf("跨任务读取应被拒绝: item=%v err=%v", it, err)
	}
	if it, err := s.Get(ctx, id2, 0); err != nil || it != nil {
		t.Fatalf("taskID=0 不应读到任务条目: item=%v err=%v", it, err)
	}
	if it, err := s.Get(ctx, id1, -1); err != nil || it == nil {
		t.Fatalf("管理端全量读取应成功: item=%v err=%v", it, err)
	}
}

// ListByHost 要能按域名/IP 命中资产上登记的凭据，并保持任务隔离。
func TestListByHost(t *testing.T) {
	dsn := os.Getenv("POJUN_PG_DSN")
	if dsn == "" {
		t.Skip("POJUN_PG_DSN 未设置")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s, err := Open(dir, dir, pg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var assetID int64
	err = pg.QueryRowContext(ctx,
		`INSERT INTO assets (type, domain, root_domain, task_ids) VALUES ('root_domain',$1,$2,ARRAY[$3::bigint]) RETURNING id`,
		"pay.example.com", "example.com", 301).Scan(&assetID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.ExecContext(context.Background(), `DELETE FROM credentials WHERE task_id=$1`, 301)
		_, _ = pg.ExecContext(context.Background(), `DELETE FROM assets WHERE id=$1`, assetID)
	})

	if _, err := s.Save(ctx, SaveInput{TaskID: 301, AssetID: assetID, Kind: "password",
		Username: "admin", Secret: "p1", Privilege: "admin"}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(ctx, SaveInput{TaskID: 302, AssetID: assetID, Kind: "password",
		Username: "other-task", Secret: "p2"}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(ctx, SaveInput{TaskID: 301, Kind: "token", Username: "meta",
		Secret: "t1", Meta: []byte(`{"host":"meta.example.com"}`)}, "test"); err != nil {
		t.Fatal(err)
	}

	// 精确域名（去掉 scheme/path）。
	items, err := s.ListByHost(ctx, 301, "https://pay.example.com/login", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Username != "admin" || items[0].Privilege != "admin" {
		t.Fatalf("按域名查询应只命中本任务 admin 凭据: %+v", items)
	}
	// 根域后缀。
	items, err = s.ListByHost(ctx, 301, "example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) < 1 {
		t.Fatal("根域应命中子域资产上的凭据")
	}
	// meta.host 兜底。
	items, err = s.ListByHost(ctx, 301, "meta.example.com", "token")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Username != "meta" {
		t.Fatalf("meta.host 应命中: %+v", items)
	}
	// 任务隔离：302 的条目不能被 301 看到。
	for _, it := range items {
		if it.Username == "other-task" {
			t.Fatal("跨任务条目泄漏")
		}
	}
}
