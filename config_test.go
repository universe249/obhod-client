package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// normalise: sort all string arrays that are order-insensitive sets
func norm(v any, parent string) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = norm(x, k)
		}
		return t
	case []any:
		for i := range t {
			t[i] = norm(t[i], parent)
		}
		allStr := true
		for _, x := range t {
			if _, ok := x.(string); !ok {
				allStr = false
			}
		}
		if allStr {
			ss := make([]string, len(t))
			for i, x := range t {
				ss[i] = x.(string)
			}
			sort.Strings(ss)
			out := make([]any, len(ss))
			for i, x := range ss {
				out[i] = x
			}
			return out
		}
		if parent == "rule_set" { // definitions list: sort by tag
			sort.Slice(t, func(i, j int) bool {
				return t[i].(map[string]any)["tag"].(string) < t[j].(map[string]any)["tag"].(string)
			})
		}
		return t
	}
	return v
}

// services added after the reference config was written
var aiNew = map[string]bool{"gemini": true, "claude": true, "grok": true, "copilot": true, "perplexity": true, "mistral": true, "metaai": true, "hf": true, "openrouter": true, "poe": true, "midjourney": true, "characterai": true, "cursor": true, "githubcopilot": true, "cohere": true, "elevenlabs": true, "suno": true, "runway": true, "apex": true}

func TestMatchesHandWrittenConfig(t *testing.T) {
	st := defaultSettings()
	st.BlockIPv6 = false
	for _, s := range catalog {
		st.Services[s.ID] = !aiNew[s.ID] // added after the reference config was written
	}
	// пароли сервера берём из эталонного конфига, а не храним в коде
	orig, err := os.ReadFile("/home/claude/config.json")
	if err != nil {
		t.Skip("no reference config")
	}
	var ref map[string]any
	_ = json.Unmarshal(orig, &ref)
	pass, obfs := "", ""
	for _, o := range ref["outbounds"].([]any) {
		if om := o.(map[string]any); om["tag"] == "proxy" {
			pass, _ = om["password"].(string)
			if ob, ok := om["obfs"].(map[string]any); ok {
				obfs, _ = ob["password"].(string)
			}
		}
	}
	st.Server = Server{Type: "hysteria2", Host: "hoop.un1v249.ru", Port: 443, Password: pass,
		ObfsPassword: obfs, Insecure: true}
	// the hand-written config adds the server IP as a second direct rule; we only emit the domain rule
	b, err := configBytes(st, `C:\singbox`, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got, want map[string]any
	_ = json.Unmarshal(b, &got)
	_ = json.Unmarshal(orig, &want)

	// rule-sets are local files now: compare only the tags
	tagsOf := func(cfg map[string]any) {
		rs := cfg["route"].(map[string]any)["rule_set"].([]any)
		var tags []any
		for _, x := range rs {
			tags = append(tags, x.(map[string]any)["tag"])
		}
		cfg["route"].(map[string]any)["rule_set"] = tags
	}
	tagsOf(got)
	tagsOf(want)
	// known intentional differences
	// paths use the host separator; the test runs on Linux
	got["log"].(map[string]any)["output"] = `C:\singbox\box.log`
	got["experimental"].(map[string]any)["cache_file"].(map[string]any)["path"] = `C:\singbox\cache.db`
	delete(got["route"].(map[string]any), "find_process")
	// remote DNS goes over TCP through the tunnel (UDP over Hysteria2 was unreliable)
	for _, sv := range got["dns"].(map[string]any)["servers"].([]any) {
		if sm := sv.(map[string]any); sm["tag"] == "dns-remote" {
			sm["type"] = "udp"
		}
	}
	delete(got["experimental"].(map[string]any), "clash_api")
	// leak-test echo hosts are our own addition
	dropLeak := func(list []any) []any {
		var out []any
		for _, r := range list {
			if mm, ok := r.(map[string]any); ok {
				if d, ok := mm["domain"].([]any); ok && len(d) > 0 {
					if s, _ := d[0].(string); s == leakProxyHost || s == leakDirectHost {
						continue
					}
				}
			}
			out = append(out, r)
		}
		return out
	}
	// the local test proxy (probe.go) is our own addition: inbound and its auth_user rules
	got["inbounds"] = got["inbounds"].([]any)[:1]
	var keep []any
	for _, r := range got["route"].(map[string]any)["rules"].([]any) {
		if mm, ok := r.(map[string]any); ok {
			if _, has := mm["auth_user"]; has {
				continue
			}
		}
		keep = append(keep, r)
	}
	got["route"].(map[string]any)["rules"] = keep
	got["route"].(map[string]any)["rules"] = dropLeak(got["route"].(map[string]any)["rules"].([]any))
	got["dns"].(map[string]any)["rules"] = dropLeak(got["dns"].(map[string]any)["rules"].([]any))
	// reverse DNS mapping and the longer sniff window are deliberate additions to the reference
	delete(got["dns"].(map[string]any), "reverse_mapping")
	for _, r := range got["route"].(map[string]any)["rules"].([]any) {
		if mm, ok := r.(map[string]any); ok && mm["action"] == "sniff" {
			delete(mm, "timeout")
		}
	}
	// deliberate additions since the reference was written: more TikTok CDN domains and the built-in Steam direct apps
	extraTT := map[string]bool{"tiktokv.us": true, "tiktokw.us": true, "tiktokcdn-eu.com": true, "ibyteimg.com": true, "byteimg.com": true, "bytedance.com": true,
		"bytefcdn-oversea.com": true, "byted.org": true, "ttwstatic.com": true, "ttlivecdn.com": true, "musical.ly": true, "snssdk.com": true, "isnssdk.com": true, "pstatp.com": true}
	steam := map[string]bool{}
	for _, x := range builtinDirectApps {
		steam[x] = true
	}
	cut := func(v any, drop map[string]bool) []any {
		var out []any
		for _, x := range v.([]any) {
			if !drop[x.(string)] {
				out = append(out, x)
			}
		}
		return out
	}
	var rules2 []any
	for _, r := range got["route"].(map[string]any)["rules"].([]any) {
		if mm, ok := r.(map[string]any); ok {
			if _, has := mm["domain_suffix"]; has {
				mm["domain_suffix"] = cut(mm["domain_suffix"], extraTT)
			}
			if _, has := mm["process_name"]; has {
				if l := cut(mm["process_name"], steam); len(l) == 0 {
					continue
				} else {
					mm["process_name"] = l
				}
			}
		}
		rules2 = append(rules2, r)
	}
	got["route"].(map[string]any)["rules"] = rules2
	for _, key := range []string{"rules"} {
		if dr, ok := got["dns"].(map[string]any)[key].([]any); ok {
			for _, r := range dr {
				if mm, ok := r.(map[string]any); ok {
					if _, has := mm["domain_suffix"]; has {
						mm["domain_suffix"] = cut(mm["domain_suffix"], extraTT)
					}
				}
			}
		}
	}
	// reference has the extra ip_cidr rule for the VPS IP; drop it for comparison
	wr := want["route"].(map[string]any)["rules"].([]any)
	var wr2 []any
	for _, r := range wr {
		if mm, ok := r.(map[string]any); ok {
			if c, ok := mm["ip_cidr"].([]any); ok && len(c) == 1 && strings.HasSuffix(fmt.Sprint(c[0]), "/32") {
				continue
			}
		}
		wr2 = append(wr2, r)
	}
	want["route"].(map[string]any)["rules"] = wr2

	g := norm(got, "")
	w := norm(want, "")
	if !reflect.DeepEqual(g, w) {
		gb, _ := json.MarshalIndent(g, "", " ")
		wb, _ := json.MarshalIndent(w, "", " ")
		os.WriteFile("/tmp/got.json", gb, 0o644)
		os.WriteFile("/tmp/want.json", wb, 0o644)
		t.Fatal("generated config differs from hand-written one; see /tmp/got.json and /tmp/want.json")
	}
}

func TestLinks(t *testing.T) {
	s, err := parseLink("hysteria2://Test1Pass@hoop.example.ru:443?downmbps=800&upmbps=800&security=tls&insecure=1&obfs=salamander&obfs-password=TestObfsPassword&fastopen=0#hysteria2-57924")
	if err != nil || s.Type != "hysteria2" || s.Password != "Test1Pass" || !s.Insecure || s.ObfsPassword == "" || s.Port != 443 || s.Name != "hysteria2-57924" {
		t.Fatalf("hy2: %+v %v", s, err)
	}
	s, err = parseLink("vless://00000000-0000-4000-8000-000000000001@hoop.example.ru:8443?type=tcp&security=tls&flow=xtls-rprx-vision#vlesska")
	if err != nil || s.Type != "vless" || s.Flow != "xtls-rprx-vision" || s.Port != 8443 || s.Security != "tls" {
		t.Fatalf("vless: %+v %v", s, err)
	}
	if _, err := parseLink("vmess://x@y:1"); err == nil {
		t.Fatal("expected error")
	}
}

const xhttpLink = "vless://00000000-0000-4000-8000-000000000000@203.0.113.7:34628?encryption=none&extra=%7B%22mode%22%3A%22auto%22%2C%22xPaddingBytes%22%3A%22100-1000%22%7D&fp=firefox&host=&mode=auto&path=%2F&pbk=PUBKEYPUBKEY&security=reality&sid=46a48536022ed1&sni=wordpress.com&spx=%2F69ce12e1d219970&support-x25519mlkem768=true&type=xhttp&x_padding_bytes=100-1000#Main-Admin"

func TestXhttp(t *testing.T) {
	srv, err := parseLink(xhttpLink)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Network != "xhttp" || srv.Security != "reality" || srv.SNI != "wordpress.com" || srv.Fingerprint != "firefox" ||
		srv.PublicKey != "PUBKEYPUBKEY" || srv.ShortID != "46a48536022ed1" || srv.Spx != "/69ce12e1d219970" ||
		srv.WSPath != "/" || srv.XMode != "auto" || srv.Port != 34628 || srv.Name != "Main-Admin" {
		t.Fatalf("bad parse: %+v", srv)
	}
	st := defaultSettings()
	st.Server = srv
	xb, err := xrayConfigBytes(st, "/d")
	if err != nil {
		t.Fatal(err)
	}
	var x map[string]any
	if err := json.Unmarshal(xb, &x); err != nil {
		t.Fatal(err)
	}
	ob := x["outbounds"].([]any)[0].(map[string]any)
	ss := ob["streamSettings"].(map[string]any)
	if ss["network"] != "xhttp" || ss["security"] != "reality" {
		t.Fatalf("stream: %v", ss)
	}
	xh := ss["xhttpSettings"].(map[string]any)
	extra := xh["extra"].(map[string]any)
	if extra["xPaddingBytes"] != "100-1000" || extra["mode"] != nil || xh["mode"] != "auto" || xh["path"] != "/" {
		t.Fatalf("xhttp: %v", xh)
	}
	rs := ss["realitySettings"].(map[string]any)
	if rs["serverName"] != "wordpress.com" || rs["publicKey"] != "PUBKEYPUBKEY" || rs["spiderX"] != "/69ce12e1d219970" || rs["fingerprint"] != "firefox" {
		t.Fatalf("reality: %v", rs)
	}
	if x["inbounds"].([]any)[0].(map[string]any)["port"].(float64) != 10808 {
		t.Fatal("socks port")
	}

	// sing-box side: socks outbound to the local Xray + xray.exe must be direct
	cb, err := configBytes(st, "/d", nil)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	_ = json.Unmarshal(cb, &c)
	px := c["outbounds"].([]any)[0].(map[string]any)
	if px["type"] != "socks" || px["server"] != "127.0.0.1" || px["server_port"].(float64) != 10808 {
		t.Fatalf("outbound: %v", px)
	}
	found := false
	for _, r := range c["route"].(map[string]any)["rules"].([]any) {
		rm := r.(map[string]any)
		if pn, ok := rm["process_name"].([]any); ok && len(pn) == 1 && pn[0] == "xray.exe" && rm["outbound"] == "direct" {
			found = true
		}
	}
	if !found {
		t.Fatal("no direct rule for xray.exe")
	}
	if fullHash(st, "/d", nil) == "" {
		t.Fatal("hash")
	}
	// plain hysteria2 profile must not need Xray
	if needsXray(Server{Type: "hysteria2"}) {
		t.Fatal("hy2 should not need xray")
	}
}

func TestRuleSetDownloadAndFallback(t *testing.T) {
	good := "SRS\x01" + strings.Repeat("x", 40)
	mux := http.NewServeMux()
	mux.HandleFunc("/html", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>blocked</html>")) })
	mux.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(good)) })
	ts := httptest.NewServer(mux)
	defer ts.Close()
	dir := t.TempDir()

	// primary URL returns HTML, mirror returns the real file -> must succeed via the mirror
	if err := downloadRuleSet(dir, RuleSet{"geosite-x", []string{ts.URL + "/html", ts.URL + "/404", ts.URL + "/ok"}}); err != nil {
		t.Fatal(err)
	}
	if !validSRS(ruleSetPath(dir, "geosite-x")) {
		t.Fatal("file not valid")
	}
	// all sources bad -> error and no file
	if err := downloadRuleSet(dir, RuleSet{"geosite-y", []string{ts.URL + "/html", ts.URL + "/404"}}); err == nil {
		t.Fatal("expected error")
	}
	if validSRS(ruleSetPath(dir, "geosite-y")) {
		t.Fatal("bad file must not be saved")
	}
}

func TestSkipAndTags(t *testing.T) {
	st := defaultSettings()
	st.Server = Server{Type: "hysteria2", Host: "h.example", Port: 443, Password: "p"}
	all := neededTags(st)
	if len(all) < 9 {
		t.Fatalf("tags: %v", all)
	}
	skip := map[string]bool{"geosite-youtube": true, "ru-blocked-ip": true}
	cfg, err := buildConfig(st, "/d", skip)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(cfg)
	s := string(b)
	if strings.Contains(s, "geosite-youtube") || strings.Contains(s, "ru-blocked-ip") {
		t.Fatal("skipped lists must not appear in the config")
	}
	if !strings.Contains(s, "geosite-instagram") || !strings.Contains(s, `"type":"local"`) {
		t.Fatal("other lists must stay, as local files")
	}
}

func TestParseTarget(t *testing.T) {
	for in, want := range map[string]string{"Instagram.com": "instagram.com", "https://X.com/a?b": "x.com", "host.tld:8443": "host.tld"} {
		h, _, err := parseTarget(in)
		if err != nil || h != want {
			t.Fatalf("%s -> %s %v", in, h, err)
		}
	}
	if _, _, err := parseTarget("  "); err == nil {
		t.Fatal("empty must fail")
	}
}

func TestProfilesAndSubscription(t *testing.T) {
	body := "hysteria2://pw@h1.example.com:443/?sni=x#One\nvless://11111111-1111-1111-1111-111111111111@h2.example.com:8443?security=tls&type=tcp&sni=y#Two\nvmess://abc\n"
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	for _, in := range []string{body, enc} {
		list, skipped := parseLinks(in)
		if len(list) != 2 || skipped != 1 {
			t.Fatalf("got %d servers, %d skipped", len(list), skipped)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(enc)) }))
	defer srv.Close()
	txt, err := fetchSubscription(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := parseLinks(txt)
	st := defaultSettings()
	if n := addProfiles(&st, list); n != 2 {
		t.Fatal(n)
	}
	if n := addProfiles(&st, list); n != 0 {
		t.Fatal("duplicates added")
	}
	st.Server = st.Profiles[1]
	if profileIndex(st) != 1 {
		t.Fatal("index")
	}
}

func TestIPv6Block(t *testing.T) {
	st := defaultSettings()
	if st.BlockIPv6 {
		t.Fatal("must be off by default")
	}
	st.BlockIPv6 = true
	st.Server = Server{Type: "hysteria2", Host: "1.2.3.4", Port: 443, Password: "x"}
	b, err := configBytes(st, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "fdfe:dcba:9876::1/126") || !strings.Contains(string(b), "::/0") {
		t.Fatal("ipv6 protection missing")
	}
	st.BlockIPv6 = false
	b, _ = configBytes(st, t.TempDir(), nil)
	if strings.Contains(string(b), "::/0") {
		t.Fatal("should be off")
	}
}

func TestFailoverNext(t *testing.T) {
	a := &App{dataDir: t.TempDir()}
	a.st = defaultSettings()
	a.st.Profiles = []Server{{Name: "A", Type: "hysteria2", Host: "a", Port: 1, Password: "x"}, {Name: "B", Type: "hysteria2", Host: "b", Port: 1, Password: "y"}}
	a.st.Server = a.st.Profiles[0]
	if n, ok := a.failoverNext(); !ok || n != "B" || a.st.Server.Host != "b" {
		t.Fatal(n, ok)
	}
	if n, _ := a.failoverNext(); n != "A" {
		t.Fatal("wraparound", n)
	}
	a.st.Failover = false
	if _, ok := a.failoverNext(); ok {
		t.Fatal("disabled")
	}
}

func TestReportDoesNotMaskLiveSettings(t *testing.T) {
	a := &App{dataDir: t.TempDir(), core: &Core{}}
	a.st = defaultSettings()
	a.st.Server = Server{Type: "hysteria2", Host: "a", Port: 1, Password: "secret"}
	a.st.Profiles = []Server{a.st.Server}
	rec := httptest.NewRecorder()
	a.handleReport(rec, httptest.NewRequest("GET", "/api/report", nil))
	if a.st.Profiles[0].Password != "secret" || a.st.Server.Password != "secret" {
		t.Fatal("report masked live settings")
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatal("secret leaked into the report")
	}
}

func TestGlobalMode(t *testing.T) {
	st := defaultSettings()
	st.Server = Server{Type: "hysteria2", Host: "1.2.3.4", Port: 443, Password: "x"}
	st.Mode = "global"
	b, err := configBytes(st, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Route struct{ Final string }
		DNS   struct{ Final string }
	}
	json.Unmarshal(b, &cfg)
	if cfg.Route.Final != "proxy" || cfg.DNS.Final != "dns-remote" || !strings.Contains(string(b), `"xn--p1ai"`) {
		t.Fatalf("global mode config wrong: %+v", cfg)
	}
}

func TestUpdateFlow(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	oldKey := updatePubKey
	updatePubKey = base64.StdEncoding.EncodeToString(pub)
	defer func() { updatePubKey = oldKey }()

	// build a zip holding a fake exe
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	f, _ := zw.Create("Папка v9.9/Прога.exe")
	exe := append([]byte("MZ"), bytes.Repeat([]byte{1}, 2<<20)...)
	f.Write(exe)
	zw.Close()
	sum := sha256.Sum256(zb.Bytes())
	man, _ := json.Marshal(updateManifest{Version: "9.9", File: "o.zip", SHA256: hex.EncodeToString(sum[:])})
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, man))

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/" + updateRepo + "/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v9.9","body":"notes","assets":[{"name":"manifest.json","browser_download_url":"%[1]s/m"},{"name":"manifest.json.sig","browser_download_url":"%[1]s/s"},{"name":"o.zip","browser_download_url":"%[1]s/z"}]}`, srv.URL)
		case "/m":
			w.Write(man)
		case "/s":
			w.Write([]byte(sig))
		case "/z":
			w.Write(zb.Bytes())
		}
	}))
	defer srv.Close()
	updateAPIBase = srv.URL
	appVersion = "3.4"
	defer func() { appVersion = "dev" }()

	var u Updater
	if err := u.check(); err != nil {
		t.Fatal(err)
	}
	if s := u.snapshot(); s["available"] != true || s["latest"] != "9.9" {
		t.Fatalf("%v", s)
	}
	got, err := u.download()
	if err != nil || !bytes.Equal(got, exe) {
		t.Fatal("download", err)
	}
	dir := t.TempDir()
	cur := filepath.Join(dir, "app.exe")
	os.WriteFile(cur, []byte("old"), 0o755)
	if err := swapExe(cur, got); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cur + ".bak"); string(b) != "old" {
		t.Fatal("no backup")
	}
	if b, _ := os.ReadFile(cur); !bytes.Equal(b, exe) {
		t.Fatal("not replaced")
	}

	// tampered signature must be rejected
	sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte("other")))
	if err := u.check(); err == nil {
		t.Fatal("bad signature accepted")
	}
	// tampered archive must be rejected
	sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, man))
	zb.WriteString("x")
	if err := u.check(); err != nil {
		t.Fatal(err)
	}
	if _, err := u.download(); err == nil {
		t.Fatal("modified archive accepted")
	}
}

func TestVersionCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"3.5", "3.4", true}, {"3.4", "3.4", false}, {"3.10", "3.9", true}, {"v4", "3.9", true}, {"3.4", "dev", false}} {
		if got := newerVersion(c.a, c.b); got != c.want {
			t.Fatalf("%v: %v", c, got)
		}
	}
}

func TestFakeIPOptIn(t *testing.T) {
	st := defaultSettings()
	st.Mode = "smart"
	st.Server = Server{Type: "vless", Host: "1.2.3.4", Port: 443, UUID: "u", Name: "s"}
	st.CustomDomains = []string{"example.com"}
	has := func(c map[string]any) bool {
		for _, sv := range c["dns"].(map[string]any)["servers"].([]map[string]any) {
			if sv["type"] == "fakeip" {
				return true
			}
		}
		return false
	}
	c, err := buildConfig(st, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if has(c) {
		t.Fatal("fakeip must be off by default")
	}
	st.FakeIP = true
	c, _ = buildConfig(st, t.TempDir(), nil)
	if !has(c) {
		t.Fatal("fakeip missing")
	}
	st.Mode = "global"
	c, _ = buildConfig(st, t.TempDir(), nil)
	if has(c) {
		t.Fatal("no fakeip in global")
	}
}
