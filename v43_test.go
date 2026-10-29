package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHopAndCIDR(t *testing.T) {
	got := normHop("20000-30000, 40000, bad, 70000-80000, 5-1")
	if len(got) != 2 || got[0] != "20000:30000" || got[1] != "40000" {
		t.Fatalf("%v", got)
	}
	if normCIDR("1.2.3.4") != "1.2.3.4/32" || normCIDR("10.0.0.0/8") != "10.0.0.0/8" || normCIDR("zzz") != "" {
		t.Fatal("cidr")
	}
	st := defaultSettings()
	st.Server = Server{Type: "hysteria2", Host: "h.example.com", Port: 443, Password: "p", HopPorts: "20000-30000"}
	st.CustomCIDRs = []string{"203.0.113.7"}
	b, err := configBytes(st, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"server_ports"`) || !strings.Contains(s, "20000:30000") || !strings.Contains(s, "203.0.113.7/32") {
		t.Fatalf("config misses hop/cidr")
	}
	if strings.Contains(s, `"server_port"`) {
		t.Fatal("server_port must be dropped when hopping")
	}
}

func TestHistoryOutage(t *testing.T) {
	h := newHistory(t.TempDir())
	t0 := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		h.Record(t0.Add(time.Duration(i)*10*time.Second), true, 50)
	}
	var d time.Duration
	for i := 0; i < 40; i++ { // 400 s of failures
		d = h.Record(t0.Add(time.Minute+time.Duration(i)*10*time.Second), false, 0)
	}
	if d < 5*time.Minute {
		t.Fatalf("outage %v", d)
	}
	h.Record(t0.Add(10*time.Minute), true, 60)
	v := h.View(t0.Add(11 * time.Minute))
	outs := v["outages"].([]Outage)
	if len(outs) != 1 || outs[0].End == 0 || outs[0].Start != t0.Add(time.Minute).Unix() {
		t.Fatalf("%+v", outs)
	}
	if up := v["uptime"].(float64); up <= 0 || up >= 100 {
		t.Fatalf("uptime %v", up)
	}
	h.Flush()
	h2 := newHistory(filepath.Dir(h.path))
	if len(h2.d.Outages) != 1 {
		t.Fatal("not persisted")
	}
	// two failures then success are not an outage
	h3 := newHistory(t.TempDir())
	h3.Record(t0, false, 0)
	h3.Record(t0.Add(time.Second), false, 0)
	h3.Record(t0.Add(2*time.Second), true, 10)
	if len(h3.d.Outages) != 0 {
		t.Fatal("false outage")
	}
	// tunnel stop closes it
	h3.Record(t0.Add(10*time.Second), false, 0)
	h3.Record(t0.Add(11*time.Second), false, 0)
	h3.Record(t0.Add(12*time.Second), false, 0)
	h3.TunnelStopped(t0.Add(20 * time.Second))
	if h3.d.Outages[0].End == 0 {
		t.Fatal("not closed")
	}
}

func TestHints(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("+0300 2026-10-13 16:58:17 INFO [1 5ms] dns: exchanged A pass.yandex.ru. 465 IN A 213.180.204.51\n")
	for i := 0; i < 4; i++ {
		sb.WriteString("+0300 2026-10-13 16:55:29 ERROR [2 5.0s] connection: open connection to 213.180.204.51:443 using outbound/direct[direct]: dial tcp 213.180.204.51:443: i/o timeout\n")
	}
	for i := 0; i < 2; i++ {
		sb.WriteString("+0300 2026-10-13 16:55:29 ERROR [2 5.0s] connection: open connection to rare.example.org:443 using outbound/direct[direct]: dial tcp 1.1.1.1:443: i/o timeout\n")
	}
	for i := 0; i < 3; i++ {
		sb.WriteString("+0300 2026-10-13 16:55:29 ERROR [2 5.0s] connection: open connection to cdn.blocked.io:443 using outbound/direct[direct]: dial tcp 1.1.1.1:443: connection reset by peer\n")
	}
	st := defaultSettings()
	hs := parseHints(sb.String(), st)
	if len(hs) != 2 || hs[0].Name != "yandex.ru" || hs[1].Name != "blocked.io" {
		t.Fatalf("%+v", hs)
	}
	st.CustomDomains = []string{"blocked.io"}
	st.IgnoredHints = []string{"yandex.ru"}
	if hs := parseHints(sb.String(), st); len(hs) != 0 {
		t.Fatalf("covered/ignored still shown: %+v", hs)
	}
}

func TestJudgeLeak(t *testing.T) {
	v := judgeLeak(LeakResult{DirectIP: "1.1.1.1", ProxyIP: "1.1.1.1"}, true)
	if v[0].OK {
		t.Fatal("same ip must fail")
	}
	v = judgeLeak(LeakResult{DirectIP: "1.1.1.1", ProxyIP: "2.2.2.2", V6IP: "2001:db8::1"}, false)
	if !v[0].OK || v[len(v)-1].OK {
		t.Fatalf("%+v", v)
	}
}

func TestCLI(t *testing.T) {
	if !isCLI([]string{"status"}) || isCLI([]string{"-background"}) || isCLI(nil) {
		t.Fatal("isCLI")
	}
	dir := t.TempDir()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ck, err := r.Cookie("singui"); err != nil || ck.Value != "0123456789abcdef0123" {
			w.WriteHeader(403)
			return
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/api/state":
			json.NewEncoder(w).Encode(map[string]any{"running": true, "health": "ok", "pingMs": 42, "serverName": "NL", "version": "4.3"})
		case "/api/settings":
			json.NewEncoder(w).Encode(map[string]any{"profiles": []map[string]string{{"Name": "A", "Host": "a.com"}, {"Name": "B", "Host": "b.com"}}})
		case "/api/ping":
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "ms": 77})
		default:
			json.NewEncoder(w).Encode(map[string]any{"ok": true})
		}
	}))
	defer srv.Close()
	_ = dir
	c := &cliClient{base: srv.URL, token: "0123456789abcdef0123", hc: srv.Client()}
	var s struct{ PingMs int }
	if err := c.call("GET", "/api/state", nil, &s); err != nil || s.PingMs != 42 {
		t.Fatalf("%v %+v", err, s)
	}
	if err := c.call("POST", "/api/core/start", nil, nil); err != nil {
		t.Fatal(err)
	}
	bad := &cliClient{base: srv.URL, token: "wrong", hc: srv.Client()}
	if bad.call("GET", "/api/state", nil, nil) == nil {
		t.Fatal("expected auth error")
	}
	var out, er bytes.Buffer
	if code := runCLI([]string{"help"}, dir, &out, &er); code != 0 || !strings.Contains(out.String(), "status") {
		t.Fatal("help")
	}
	if code := runCLI([]string{"status"}, dir, &out, &er); code != 2 { // no token file
		t.Fatalf("code %d", code)
	}
}

func TestGeminiService(t *testing.T) {
	st := defaultSettings()
	st.Server = Server{Type: "vless", Host: "1.2.3.4", Port: 8443, UUID: "u", Security: "tls", SNI: "x.com", Network: "tcp"}
	st.Services["gemini"] = true
	b, err := configBytes(st, t.TempDir(), nil)
	if err != nil || !strings.Contains(string(b), "gemini.google.com") {
		t.Fatalf("gemini not routed: %v", err)
	}
}

func TestDedupeSettings(t *testing.T) {
	s := normalizeSettings(Settings{CustomCIDRs: []string{"1.2.3.4", "1.2.3.4", ""}})
	if len(s.CustomCIDRs) != 1 {
		t.Fatalf("%v", s.CustomCIDRs)
	}
	if got := addUnique([]string{"a"}, "a"); len(got) != 1 {
		t.Fatal("addUnique")
	}
}

func multiSettings() Settings {
	st := defaultSettings()
	st.APISecret = "secret123"
	st.Server = Server{Name: "EU", Type: "vless", Host: "1.1.1.1", Port: 8443, UUID: "u1", Security: "tls", SNI: "a.com", Network: "tcp"}
	st.Profiles = []Server{
		st.Server,
		{Name: "US", Type: "vless", Host: "2.2.2.2", Port: 443, UUID: "u2", Security: "tls", SNI: "b.com", Network: "tcp"},
		{Name: "NL", Type: "hysteria2", Host: "nl.example.com", Port: 443, Password: "p"},
	}
	return st
}

func cfgOf(t *testing.T, st Settings) map[string]any {
	t.Helper()
	b, err := configBytes(st, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func outTags(cfg map[string]any) map[string]string {
	tags := map[string]string{}
	for _, o := range cfg["outbounds"].([]any) {
		mm := o.(map[string]any)
		tags[mm["tag"].(string)] = mm["type"].(string)
	}
	return tags
}

func TestFragment(t *testing.T) {
	st := multiSettings()
	hasFrag := func(cfg map[string]any, tag string) bool {
		for _, o := range cfg["outbounds"].([]any) {
			mm := o.(map[string]any)
			if mm["tag"] != tag {
				continue
			}
			t2, _ := mm["tls"].(map[string]any)
			return t2 != nil && t2["fragment"] == true
		}
		t.Fatalf("no outbound %s", tag)
		return false
	}
	if hasFrag(cfgOf(t, st), "proxy") {
		t.Fatal("fragment must be off by default")
	}
	st.Fragment = true
	if !hasFrag(cfgOf(t, st), "proxy") {
		t.Fatal("fragment missing")
	}
	// the server's own choice wins over the global switch
	st.Server.Frag = "off"
	if hasFrag(cfgOf(t, st), "proxy") {
		t.Fatal("server frag=off ignored")
	}
}

func mustBytes(t *testing.T, st Settings) []byte {
	b, err := configBytes(st, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAutoBestAndExtras(t *testing.T) {
	st := multiSettings()
	tags := outTags(cfgOf(t, st))
	if tags["proxy"] != "vless" || tags["srv-0"] == "" || tags["srv-1"] == "" || tags["srv-2"] != "hysteria2" {
		t.Fatalf("%v", tags)
	}
	st.AutoBest = true
	tags = outTags(cfgOf(t, st))
	if tags["proxy"] != "vless" {
		t.Fatalf("автовыбор без подписки сервиса не включается: %v", tags)
	}
	st.SubURL, st.Server.FromSub = "https://hoop.un1v249.ru:8444/sub/kabc", true // подписка нашего сервиса
	tags = outTags(cfgOf(t, st))
	if tags["proxy"] != "urltest" || tags["proxy-main"] != "vless" {
		t.Fatalf("autobest: %v", tags)
	}
	// every server address must stay direct so the tunnel does not loop
	s := string(mustBytes(t, st))
	for _, h := range []string{"1.1.1.1/32", "2.2.2.2/32", "nl.example.com"} {
		if !strings.Contains(s, h) {
			t.Fatalf("no direct rule for %s", h)
		}
	}
	// a single server gets no base extras and no urltest (only the tuner's "ways")
	one := defaultSettings()
	one.APISecret = "x"
	one.Server = st.Server
	one.AutoBest = true
	tags = outTags(cfgOf(t, one))
	for tag := range tags {
		if tag == "srv-0" || tags[tag] == "urltest" {
			t.Fatalf("single server: %v", tags)
		}
	}
}

func TestGroupServer(t *testing.T) {
	st := multiSettings()
	st.Services["gemini"] = true
	st.GroupServers = map[string]string{"ИИ и нейросети": "US"}
	cfg := cfgOf(t, st)
	found := false
	for _, r := range cfg["route"].(map[string]any)["rules"].([]any) {
		mm := r.(map[string]any)
		if mm["outbound"] == "srv-1" {
			if d, ok := mm["domain_suffix"].([]any); ok {
				for _, x := range d {
					if x == "gemini.google.com" {
						found = true
					}
				}
			}
		}
	}
	if !found {
		t.Fatal("gemini not pinned to the US server")
	}
	// unknown server name: ignored, nothing breaks
	st.GroupServers = map[string]string{"ИИ и нейросети": "nope"}
	cfgOf(t, st)
}

func TestProbeInboundAndUsers(t *testing.T) {
	st := multiSettings()
	cfg := cfgOf(t, st)
	var probe map[string]any
	for _, in := range cfg["inbounds"].([]any) {
		if in.(map[string]any)["tag"] == "probe-in" {
			probe = in.(map[string]any)
		}
	}
	if probe == nil || probe["listen"] != "127.0.0.1" || int(probe["listen_port"].(float64)) != st.APIPort+1 {
		t.Fatalf("%v", probe)
	}
	users := map[string]bool{}
	for _, u := range probe["users"].([]any) {
		users[u.(map[string]any)["username"].(string)] = true
	}
	for _, want := range []string{"route", "proxy", "direct", "s0", "s1", "s2"} {
		if !users[want] {
			t.Fatalf("probe user %s missing: %v", want, users)
		}
	}
}

func TestSvcJudges(t *testing.T) {
	get := func(id string) svcProbe {
		for _, p := range svcProbes {
			if p.ID == id {
				return p
			}
		}
		t.Fatal(id)
		return svcProbe{}
	}
	if lv, _ := get("gemini").Judge(200, "", "Gemini isn't currently supported in your country"); lv != lvBad {
		t.Fatal("gemini blocked")
	}
	if lv, _ := get("gemini").Judge(200, "", "<html>hello</html>"); lv != lvOK {
		t.Fatal("gemini ok")
	}
	if lv, _ := get("claude").Judge(200, "https://claude.ai/app-unavailable-in-region", ""); lv != lvBad {
		t.Fatal("claude region")
	}
	if lv, _ := get("openai").Judge(403, "", `{"error":{"code":"unsupported_country_region_territory"}}`); lv != lvBad {
		t.Fatal("openai region")
	}
	if lv, _ := get("openai").Judge(401, "", ""); lv != lvOK {
		t.Fatal("openai ok")
	}
	if lv, _ := get("anthropic").Judge(403, "", ""); lv != lvBad {
		t.Fatal("anthropic 403")
	}
}

func TestSpeedAndProbeClient(t *testing.T) {
	// proxy auth: the probe client must send Basic credentials with the user name that picks the exit
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Proxy-Authorization")
		w.Write(bytes.Repeat([]byte("x"), 200000))
	}))
	defer srv.Close()
	st := defaultSettings()
	st.APISecret = "pw"
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	st.APIPort = port - 1
	cl := probeClient(st, probeUserProxy, 5*time.Second)
	resp, err := cl.Get("http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Fatalf("no proxy auth: %q", gotAuth)
	}
	dec, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(gotAuth, "Basic "))
	if string(dec) != "proxy:pw" {
		t.Fatalf("%s", dec)
	}
}

func TestSniffAndReverseMapping(t *testing.T) {
	st := multiSettings()
	out := string(mustBytes(t, st))
	if !strings.Contains(out, `"reverse_mapping": true`) || !strings.Contains(out, `"timeout": "1s"`) {
		t.Fatal("reverse mapping / sniff timeout missing")
	}
}

func TestNoFragmentOnQUIC(t *testing.T) {
	o := m{"type": "hysteria2", "tls": m{"enabled": true}}
	applyFragment(o)
	if _, ok := o["tls"].(m)["fragment"]; ok {
		t.Fatal("fragment applied to hysteria2")
	}
	v := m{"type": "vless", "tls": m{"enabled": true}}
	applyFragment(v)
	if v["tls"].(m)["fragment"] != true {
		t.Fatal("fragment missing on vless")
	}
}

func TestPinnedServerIP(t *testing.T) {
	st := multiSettings()
	host := st.Server.Host
	setPins(map[string]string{host: "203.0.113.7"})
	defer setPins(map[string]string{})
	cfg := cfgOf(t, st)
	var found bool
	for _, o := range cfg["outbounds"].([]any) {
		om := o.(map[string]any)
		if om["tag"] == "proxy" {
			found = true
			if om["server"] != "203.0.113.7" {
				t.Fatalf("server not pinned: %v", om["server"])
			}
			if tls, ok := om["tls"].(map[string]any); ok && tls["server_name"] == "203.0.113.7" {
				t.Fatal("SNI must stay the domain")
			}
		}
	}
	if !found {
		t.Fatal("no proxy outbound")
	}
	setPins(map[string]string{})
	for _, o := range cfgOf(t, st)["outbounds"].([]any) {
		if om := o.(map[string]any); om["tag"] == "proxy" && om["server"] != host {
			t.Fatal("unpinned host must stay")
		}
	}
}
