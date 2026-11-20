package server

// SSH 跳板 API（v0.7.1）：登记跳板、启动本地 SOCKS5、设为代理池出口。
// 密码/私钥只进凭据保险库；接口只返回 credential_id。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/egress"
	"github.com/chu0119/pojun/traffic"
	"github.com/chu0119/pojun/vault"
)

const settingSSHProviders = "egress_ssh_providers"

type sshProviderRow struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	User         string `json:"user"`
	CredentialID int64  `json:"credential_id,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	Status       string `json:"status,omitempty"`
	SocksAddr    string `json:"socks_addr,omitempty"`
	StartedAt    string `json:"started_at,omitempty"`
}

func (s *Server) loadSSHProviders() []sshProviderRow {
	var rows []sshProviderRow
	if s.m == nil || s.m.pg == nil {
		return rows
	}
	raw, ok, _ := s.m.pg.GetSetting(settingSSHProviders)
	if ok && raw != "" {
		_ = json.Unmarshal([]byte(raw), &rows)
	}
	return rows
}

func (s *Server) saveSSHProviders(rows []sshProviderRow) error {
	b, _ := json.Marshal(rows)
	return s.m.pg.SetSetting(settingSSHProviders, string(b))
}

func (s *Server) listSSHProviders(w http.ResponseWriter, r *http.Request) {
	rows := s.loadSSHProviders()
	if s.egress != nil {
		for i := range rows {
			if addr, since, ok := s.egress.Status(rows[i].ID); ok {
				rows[i].Status = "running"
				rows[i].SocksAddr = addr
				rows[i].StartedAt = since.Format(time.RFC3339)
			}
		}
	}
	writeJSON(w, 200, map[string]any{"providers": rows})
}

func (s *Server) createSSHProvider(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil {
		writeErr(w, 503, "the credential vault is not initialized")
		return
	}
	var req struct {
		Name         string `json:"name"`
		Host         string `json:"host"`
		Port         int    `json:"port"`
		User         string `json:"user"`
		AuthKind     string `json:"auth_kind"` // key|password
		Secret       string `json:"secret"`    // private key or password; uses credential_id when empty
		CredentialID int64  `json:"credential_id"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "bad request format")
		return
	}
	if strings.TrimSpace(req.Host) == "" || req.Port <= 0 || strings.TrimSpace(req.User) == "" {
		writeErr(w, 400, "host/port/user are required")
		return
	}
	credID := req.CredentialID
	if strings.TrimSpace(req.Secret) != "" {
		kind := "key"
		if strings.EqualFold(req.AuthKind, "password") {
			kind = "password"
		}
		meta, _ := json.Marshal(map[string]any{"purpose": "ssh_jump", "host": req.Host})
		id, err := s.vault.Save(r.Context(), vault.SaveInput{
			TaskID: 0, Kind: kind, Username: req.User, Secret: req.Secret, Meta: meta,
		}, "admin")
		if err != nil {
			writeErr(w, 500, "saving the jump-host credential failed: "+err.Error())
			return
		}
		credID = id
	}
	if credID <= 0 {
		writeErr(w, 400, "secret or credential_id required")
		return
	}
	rows := s.loadSSHProviders()
	var maxID int64
	for _, x := range rows {
		if x.ID > maxID {
			maxID = x.ID
		}
	}
	row := sshProviderRow{
		ID: maxID + 1, Name: strings.TrimSpace(req.Name), Host: strings.TrimSpace(req.Host),
		Port: req.Port, User: strings.TrimSpace(req.User), CredentialID: credID,
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	if row.Name == "" {
		row.Name = row.Host
	}
	rows = append(rows, row)
	if err := s.saveSSHProviders(rows); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"provider": row})
}

func (s *Server) deleteSSHProvider(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	var removed sshProviderRow
	socksAddr := ""
	if s.egress != nil {
		if addr, _, ok := s.egress.Status(id); ok {
			socksAddr = addr
		}
		s.egress.Stop(id)
	}
	rows := s.loadSSHProviders()
	out := rows[:0]
	found := false
	for _, x := range rows {
		if x.ID == id {
			found = true
			removed = x
			continue
		}
		out = append(out, x)
	}
	if !found {
		writeErr(w, 404, "jump host not found")
		return
	}
	if err := s.saveSSHProviders(out); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 清掉加密凭据与代理池里的死 socks 条目，避免孤儿与重启后复活（v0.7.6）。
	if removed.CredentialID > 0 && s.vault != nil {
		_ = s.vault.Delete(r.Context(), removed.CredentialID, "admin")
	}
	if socksAddr != "" {
		st := s.loadProxyPool()
		kept := st.Entries[:0]
		for _, e := range st.Entries {
			if e.URL != socksAddr {
				kept = append(kept, e)
			}
		}
		st.Entries = kept
		if err := s.saveProxyPool(*st); err == nil {
			_ = s.applyProxyPool(*st)
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) sshProviderAuth(ctx context.Context, credID int64) (egress.Auth, error) {
	it, err := s.vault.Get(ctx, credID, -1)
	if err != nil {
		return egress.Auth{}, err
	}
	if it == nil {
		return egress.Auth{}, errProviderCredMissing
	}
	if it.Kind == "password" {
		return egress.Auth{Password: it.Secret}, nil
	}
	return egress.Auth{PrivateKey: it.Secret}, nil
}

var errProviderCredMissing = errors.New("jump-host credential missing (it may have been deleted)")

func (s *Server) startSSHProvider(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id <= 0 || s.egress == nil {
		writeErr(w, 400, "invalid id or the SSH jump-host manager is not initialized")
		return
	}
	var row *sshProviderRow
	rows := s.loadSSHProviders()
	for i := range rows {
		if rows[i].ID == id {
			row = &rows[i]
			break
		}
	}
	if row == nil {
		writeErr(w, 404, "jump host not found")
		return
	}
	auth, err := s.sshProviderAuth(r.Context(), row.CredentialID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	addr, err := s.egress.Start(r.Context(), egress.Provider{
		ID: row.ID, Name: row.Name, Host: row.Host, Port: row.Port, User: row.User,
	}, auth)
	if err != nil {
		writeErr(w, 500, "starting the jump host failed: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "socks_addr": addr})
}

func (s *Server) stopSSHProvider(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id <= 0 || s.egress == nil {
		writeErr(w, 400, "invalid id")
		return
	}
	stopped := s.egress.Stop(id)
	writeJSON(w, 200, map[string]any{"stopped": stopped})
}

// useSSHProvider 把跳板的本地 SOCKS5 加进代理池，并显式允许 socks5 上游。
func (s *Server) useSSHProvider(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id <= 0 || s.egress == nil {
		writeErr(w, 400, "invalid id")
		return
	}
	addr, _, ok := s.egress.Status(id)
	if !ok {
		writeErr(w, 400, "the jump host is not running yet")
		return
	}
	st := s.loadProxyPool()
	exists := false
	for _, e := range st.Entries {
		if e.URL == addr {
			exists = true
			break
		}
	}
	if !exists {
		st.Entries = append(st.Entries, traffic.PoolEntry{URL: addr, Name: "ssh-jump", Enabled: true, Weight: 1})
	}
	if err := s.m.pg.SetSetting(settingProxyAllowSocks5, "true"); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := s.saveProxyPool(*st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 只落库不热应用会让接口返回 ok 但运行中的 traffic/agent 仍用旧出口；
	// 这里立即把新池推给 MITM 代理（v0.7.6）。
	if err := s.applyProxyPool(*st); err != nil {
		writeErr(w, 500, "saved, but hot-apply failed: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "socks_addr": addr})
}
