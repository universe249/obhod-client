package main

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeDPAPI(t *testing.T) {
	protectFn = func(b []byte) ([]byte, error) {
		out := make([]byte, len(b))
		for i, c := range b {
			out[i] = c ^ 0x5a
		}
		return out, nil
	}
	unprotectFn = protectFn
	t.Cleanup(func() { protectFn, unprotectFn = dpapiProtect, dpapiUnprotect })
}

func TestSecretsEncrypted(t *testing.T) {
	fakeDPAPI(t)
	dir := t.TempDir()
	st := defaultSettings()
	st.Server = Server{Type: "hysteria2", Host: "h", Port: 443, Password: "pw-secret", ObfsPassword: "obfs-secret"}
	st.Profiles = []Server{{Type: "vless", Host: "v", Port: 8443, UUID: "uuid-secret"}}
	st.APISecret = "api-secret"
	if err := saveSettings(dir, st); err != nil {
		t.Fatal(err)
	}
	if st.Server.Password != "pw-secret" || st.Profiles[0].UUID != "uuid-secret" {
		t.Fatal("save modified caller's settings")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "settings.json"))
	for _, s := range []string{"pw-secret", "obfs-secret", "uuid-secret", "api-secret"} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("%s stored in plaintext", s)
		}
	}
	if !strings.Contains(string(raw), encPrefix) {
		t.Fatal("no encrypted values")
	}
	got := loadSettings(dir)
	if got.Server.Password != "pw-secret" || got.Server.ObfsPassword != "obfs-secret" || got.Profiles[0].UUID != "uuid-secret" || got.APISecret != "api-secret" {
		t.Fatalf("roundtrip failed: %+v", got.Server)
	}
	// legacy plaintext file still loads and gets sealed on the next save
	old := map[string]any{"server": map[string]any{"host": "x", "password": "plain"}}
	b, _ := json.Marshal(old)
	_ = os.WriteFile(filepath.Join(dir, "settings.json"), b, 0o600)
	got = loadSettings(dir)
	if got.Server.Password != "plain" {
		t.Fatal("legacy plaintext broken")
	}
	// undecryptable value (another Windows user) -> empty, not garbage
	bad := "dpapi:" + base64.StdEncoding.EncodeToString([]byte("x"))
	unprotectFn = func([]byte) ([]byte, error) { return nil, os.ErrInvalid }
	if openString(bad) != "" {
		t.Fatal("expected empty")
	}
}

func TestNoDPAPIKeepsPlain(t *testing.T) {
	protectFn, unprotectFn = nil, nil
	t.Cleanup(func() { protectFn, unprotectFn = dpapiProtect, dpapiUnprotect })
	if sealString("abc") != "abc" {
		t.Fatal("should stay plain")
	}
}

func TestExplain(t *testing.T) {
	log := "2026 ERROR start service: listen tcp 127.0.0.1:19090: bind: Only one usage of each socket address\n" +
		"WARN outbound/hysteria2[proxy]: read udp: i/o timeout\n" +
		"INFO router: connection reset by peer\n" +
		"ERROR tls: failed to verify certificate: x509: certificate has expired\n"
	ps := explainText(log)
	ids := map[string]int{}
	for _, p := range ps {
		ids[p.ID] = p.Count
	}
	for _, want := range []string{"port", "unreach", "cert"} {
		if ids[want] == 0 {
			t.Fatalf("missing %s in %+v", want, ps)
		}
	}
	if ids["reset"] != 0 {
		t.Fatal("INFO line must not count as a problem")
	}
	if len(explainText("INFO all fine")) != 0 {
		t.Fatal("false positive")
	}
}

func TestConflicts(t *testing.T) {
	c := detectConflicts([]string{"chrome.exe", "WARP-svc.exe", "avp.exe", "sing-box.exe", "warp-svc.exe"})
	if len(c) != 2 || c[0].Name != "Cloudflare WARP" || c[1].Kind != "antivirus" {
		t.Fatalf("%+v", c)
	}
	if len(detectConflicts([]string{"sing-box.exe", "xray.exe"})) != 0 {
		t.Fatal("own processes must not conflict")
	}
}

func TestStats(t *testing.T) {
	dir := t.TempDir()
	s := newStats(dir)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.Local)
	s.Record(now, []connSample{{"a", "chrome.exe", "www.youtube.com", true, 100, 1000}, {"b", "game.exe", "x.ru", false, 5, 50}})
	s.Record(now.Add(5*time.Second), []connSample{{"a", "chrome.exe", "www.youtube.com", true, 150, 3000}})
	v := s.View(now, 7)
	tot := v["total"].(bucket)
	if tot.ProxyDown != 3000 || tot.ProxyUp != 150 || tot.DirectDown != 50 {
		t.Fatalf("%+v", tot)
	}
	apps := v["apps"].([]topRow)
	if apps[0].Name != "chrome.exe" || apps[0].ProxyDown != 3000 {
		t.Fatalf("%+v", apps)
	}
	sites := v["sites"].([]topRow)
	if sites[0].Name != "youtube.com" {
		t.Fatalf("%+v", sites)
	}
	s.Flush()
	s2 := newStats(dir)
	if s2.View(now, 1)["total"].(bucket).ProxyDown != 3000 {
		t.Fatal("not persisted")
	}
	if siteKey("a.b.c.example.com") != "example.com" || siteKey("1.2.3.4") != "1.2.3.4" {
		t.Fatal("siteKey")
	}
}

func TestSlowWindow(t *testing.T) {
	var w slowWindow
	for i := 0; i < 5; i++ {
		w.add(-1)
	}
	if w.degraded(1500) {
		t.Fatal("window not full yet")
	}
	w.add(80)
	if !w.degraded(1500) {
		t.Fatal("5/6 bad must be degraded")
	}
	w.reset()
	for i := 0; i < 6; i++ {
		w.add(80)
	}
	if w.degraded(1500) {
		t.Fatal("healthy flagged")
	}
	for i := 0; i < 6; i++ {
		w.add(2500)
	}
	if !w.degraded(1500) {
		t.Fatal("slow not detected")
	}
}

func TestFailoverSlowPrefersOtherProtocol(t *testing.T) {
	a := &App{dataDir: t.TempDir()}
	h2a := Server{Name: "h2a", Type: "hysteria2", Host: "a", Port: 443, Password: "p"}
	h2b := Server{Name: "h2b", Type: "hysteria2", Host: "b", Port: 443, Password: "p"}
	vl := Server{Name: "vl", Type: "vless", Host: "c", Port: 8443, UUID: "u", Network: "tcp"}
	a.st = defaultSettings()
	a.st.Profiles = []Server{h2a, h2b, vl}
	a.st.Server = h2a
	name, ok := a.failoverSlow()
	if !ok || name != "vl" {
		t.Fatalf("got %q %v", name, ok)
	}
	a.st.SlowSwitch = false
	if _, ok := a.failoverSlow(); ok {
		t.Fatal("disabled but switched")
	}
}

func TestBackupsAndRollback(t *testing.T) {
	dir := t.TempDir()
	st := defaultSettings()
	st.Server = Server{Host: "h", Type: "vless", UUID: "u"}
	_ = saveSettings(dir, st)
	now := time.Now()
	if !backupDue(dir, now) {
		t.Fatal("first backup due")
	}
	for i := 0; i < 11; i++ {
		if _, err := makeBackup(dir, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
		// give each file a distinct mtime
		l := listBackups(dir)
		_ = os.Chtimes(filepath.Join(backupDir(dir), l[0].Name), now.Add(time.Duration(i)*time.Second), now.Add(time.Duration(i)*time.Second))
	}
	if n := len(listBackups(dir)); n != backupKeep {
		t.Fatalf("kept %d", n)
	}
	if backupDue(dir, now.Add(time.Hour)) {
		t.Fatal("fresh backup, not due")
	}
	if !backupDue(dir, now.Add(8*24*time.Hour)) {
		t.Fatal("week old, due")
	}

	exe := filepath.Join(dir, "app.exe")
	_ = os.WriteFile(exe, []byte("NEW"), 0o755)
	_ = os.WriteFile(exe+".bak", []byte("OLD"), 0o755)
	if err := rollbackExe(exe); err != nil {
		t.Fatal(err)
	}
	b1, _ := os.ReadFile(exe)
	b2, _ := os.ReadFile(exe + ".bak")
	if string(b1) != "OLD" || string(b2) != "NEW" {
		t.Fatalf("%s %s", b1, b2)
	}
	_ = os.Remove(exe + ".bak")
	if rollbackExe(exe) == nil {
		t.Fatal("expected error without .bak")
	}
}

func TestGameModeConfig(t *testing.T) {
	st := defaultSettings()
	st.Server = Server{Type: "vless", Host: "1.2.3.4", Port: 8443, UUID: "u", Security: "tls", SNI: "x.com", Network: "tcp"}
	st.GameApps = []string{"dota2.exe"}
	has := func() bool {
		b, err := configBytes(st, t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Contains(string(b), "dota2.exe")
	}
	if has() {
		t.Fatal("game off but app present")
	}
	st.GameMode = true
	if !has() {
		t.Fatal("game on but app missing")
	}
}

func TestTrojanAndShadowsocks(t *testing.T) {
	tj, err := parseLink("trojan://pass123@example.com:443?sni=cdn.example.com&type=ws&path=%2Fws&host=h.example.com#MyTrojan")
	if err != nil || tj.Type != "trojan" || tj.Password != "pass123" || tj.Network != "ws" || tj.WSPath != "/ws" || tj.Name != "MyTrojan" {
		t.Fatalf("%+v %v", tj, err)
	}
	o, err := outboundFor(tj, 10808)
	if err != nil || o["type"] != "trojan" || o["transport"] == nil || o["tls"] == nil {
		t.Fatalf("%v %v", o, err)
	}
	if _, err := parseLink("trojan://p@h:1?type=grpc"); err == nil {
		t.Fatal("grpc must be rejected")
	}
	cred := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:s3cret"))
	ss, err := parseLink("ss://" + cred + "@1.2.3.4:8388#SS%20one")
	if err != nil || ss.Method != "chacha20-ietf-poly1305" || ss.Password != "s3cret" || ss.Host != "1.2.3.4" || ss.Port != 8388 || ss.Name != "SS one" {
		t.Fatalf("%+v %v", ss, err)
	}
	legacy := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw@5.6.7.8:443"))
	ss2, err := parseLink("ss://" + legacy + "#old")
	if err != nil || ss2.Method != "aes-256-gcm" || ss2.Host != "5.6.7.8" || ss2.Port != 443 {
		t.Fatalf("%+v %v", ss2, err)
	}
	if _, err := parseLink("ss://" + cred + "@1.2.3.4:8388?plugin=obfs-local"); err == nil {
		t.Fatal("plugin must be rejected")
	}
	o, _ = outboundFor(ss, 10808)
	if o["type"] != "shadowsocks" || o["method"] != "chacha20-ietf-poly1305" {
		t.Fatalf("%v", o)
	}
	// full config builds
	st := defaultSettings()
	st.Server = tj
	if _, err := configBytes(st, t.TempDir(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestPingProfiles(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	res := pingProfiles([]Server{
		{Type: "vless", Host: "127.0.0.1", Port: port},
		{Type: "hysteria2", Host: "127.0.0.1", Port: port},
		{Type: "trojan", Host: "127.0.0.1", Port: 1},
	}, pingOpts{})
	if res[0].Ms < 0 || res[1].Note != "udp" || res[2].Ms != -1 {
		t.Fatalf("%+v", res)
	}
}

func TestRefreshSubscription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("vless://u1@a.example.com:8443?security=tls#A\ntrojan://p@b.example.com:443#B\n"))
	}))
	defer srv.Close()
	a := &App{dataDir: t.TempDir()}
	a.st = defaultSettings()
	if _, err := a.refreshSubscription(); err == nil {
		t.Fatal("no url yet")
	}
	a.st.SubURL = srv.URL
	n, err := a.refreshSubscription()
	if err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	if n, _ := a.refreshSubscription(); n != 0 {
		t.Fatal("duplicates added")
	}
}

func TestParseHex(t *testing.T) {
	if v, ok := parseHex("#0f1317"); !ok || v != 0x17130f {
		t.Fatalf("%x %v", v, ok)
	}
	for _, bad := range []string{"", "0f1317", "#fff", "#gggggg", "#0f13171"} {
		if _, ok := parseHex(bad); ok {
			t.Fatal("accepted " + bad)
		}
	}
}
