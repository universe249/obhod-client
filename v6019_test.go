package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCoreTagsMatchByAddressNotIndex(t *testing.T) {
	cfg := []byte(`{"outbounds":[
		{"type":"vless","tag":"proxy","server":"a.ru","server_port":443},
		{"type":"hysteria2","tag":"srv-1","server":"h.ru","server_port":443},
		{"type":"hysteria2","tag":"srv-1-frag","server":"h.ru","server_port":4443},
		{"type":"hysteria2","tag":"srv-2","server":"1.2.3.4","server_port":4443}]}`)
	list := []Server{
		{Type: "hysteria2", Host: "1.2.3.4", Port: 4443}, // в конфигурации он под номером 2
		{Type: "vless", Host: "a.ru", Port: 443},
		{Type: "hysteria2", Host: "h.ru", Port: 443},
		{Type: "hysteria2", Host: "h.ru", Port: 4443}, // есть только «вариант» srv-1-frag — не берём
	}
	got := coreTags(cfg, list)
	if got[0] != "srv-2" || got[2] != "srv-1" || got[1] != "" || got[3] != "" {
		t.Fatalf("%v", got)
	}
}

func TestPingHysteriaThroughCoreOnlyWhenVPN(t *testing.T) {
	list := []Server{{Type: "hysteria2", Host: "h.ru", Port: 443}, {Type: "hysteria2", Host: "x.ru", Port: 443}}
	calls := 0
	o := pingOpts{VPN: true, Tags: map[int]string{0: "srv-0", 1: "srv-1"}, Delay: func(tag string) (int, error) {
		calls++
		if tag == "srv-1" {
			return 0, errors.New("timeout")
		}
		return 87, nil
	}}
	res := pingProfiles(list, o)
	if res[0].Ms != 87 || res[0].Note != "core" || res[1].Ms != -1 || res[1].Note != "core" {
		t.Fatalf("%+v", res)
	}
	o.VPN = false
	res = pingProfiles(list, o)
	if res[0].Note != "udp" || res[0].Ms != -1 || calls != 2 {
		t.Fatalf("%+v calls=%d", res, calls)
	}
}

func TestPingLocalAnswerMarkedAsTunnel(t *testing.T) {
	// при включённом VPN мгновенный ответ «из интернета» — это TUN, а не сервер; локальные адреса не трогаем
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
	res := pingProfiles([]Server{{Type: "vless", Host: "127.0.0.1", Port: port}}, pingOpts{VPN: true})
	if res[0].Ms < 0 || res[0].Note != "" {
		t.Fatalf("локальный адрес: %+v", res)
	}
}

func TestOurSubscriptionDetected(t *testing.T) {
	h := http.Header{}
	if parseSubMeta(h, "https://other.example/sub/x").Ours {
		t.Fatal("чужая подписка без метки")
	}
	if !parseSubMeta(h, "https://hoop.un1v249.ru:8444/sub/tg2").Ours || !parseSubMeta(h, "https://cdn.un1v249.su/sub/a").Ours {
		t.Fatal("наш адрес")
	}
	if parseSubMeta(h, "https://evilun1v249.ru/sub").Ours {
		t.Fatal("похожее имя — не наш")
	}
	h.Set("X-Obhod-Service", "chaiiniik")
	if !parseSubMeta(h, "https://abc.workers.dev/sub/tg2").Ours {
		t.Fatal("метка от бота (через зеркало)")
	}
}

func TestSleptBetween(t *testing.T) {
	base := time.Date(2026, 10, 19, 3, 50, 0, 0, time.UTC)
	if sleptBetween(time.Time{}, base) {
		t.Fatal("первое чтение — не сон")
	}
	if sleptBetween(base, base.Add(3*time.Second)) || sleptBetween(base, base.Add(40*time.Second)) {
		t.Fatal("обычная задержка цикла — не сон")
	}
	if !sleptBetween(base, base.Add(9*time.Hour+26*time.Minute)) {
		t.Fatal("ночь во сне")
	}
}

func multiPathSettings() Settings {
	st := defaultSettings()
	st.APISecret = "x"
	main := Server{Name: "vlesska", Type: "vless", Host: "hoop.un1v249.ru", Port: 8443, UUID: "11111111-1111-1111-1111-111111111111",
		Security: "reality", SNI: "www.example.com", PublicKey: "PR6sCOQDCTPLWvlWV3JnCdW1jpX-p1D2Kn0g0YdXd2E", ShortID: "ab", Fingerprint: "chrome", FromSub: true}
	sto, spb, other := main, main, main
	sto.Name, sto.Host = "vlesska (через Стокгольм)", "198.51.100.20"
	spb.Name, spb.Host = "vlesska (через Питер)", "198.51.100.30"
	other.Name, other.Port = "vless-2083", 2083 // другой вход — не путь к тому же серверу
	st.Server = main
	st.Profiles = []Server{main, sto, spb, other}
	st.SubURL = "https://hoop.un1v249.ru:8444/sub/kabc"
	return st
}

func TestPathsForFindsRelayCopies(t *testing.T) {
	st := multiPathSettings()
	p := pathsFor(st)
	if len(p) != 2 || p[0].Host != "198.51.100.20" || p[1].Host != "198.51.100.30" {
		t.Fatalf("%+v", p)
	}
	st.Server = st.Profiles[2] // выбран путь через Питер: остальные пути — прямой и Стокгольм
	p = pathsFor(st)
	if len(p) != 2 || p[0].Host != "hoop.un1v249.ru" {
		t.Fatalf("%+v", p)
	}
}

func TestMultiPathConfigGroup(t *testing.T) {
	st := multiPathSettings()
	cfg, err := buildConfig(st, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var group m
	tags := map[string]bool{}
	for _, o := range cfg["outbounds"].([]m) {
		tags[o["tag"].(string)] = true
		if o["tag"] == "proxy" {
			group = o
		}
	}
	if group == nil || group["type"] != "urltest" || group["interrupt_exist_connections"] != true || !tags["path-0"] || !tags["path-2"] {
		t.Fatalf("group=%v tags=%v", group, tags)
	}
	st.MultiPath = false
	cfg, _ = buildConfig(st, t.TempDir(), nil)
	for _, o := range cfg["outbounds"].([]m) {
		if o["tag"] == "proxy" && o["type"] == "urltest" {
			t.Fatal("выключено, а группа есть")
		}
	}
}

func TestServiceFeaturesOnlyWithOurSubscription(t *testing.T) {
	st := multiPathSettings()
	if !serviceOK(st) {
		t.Fatal("наша подписка")
	}
	st.SubURL = "https://other.example/sub/x"
	if serviceOK(st) {
		t.Fatal("чужая подписка без метки")
	}
	st.SubMeta = &SubMeta{Ours: true}
	if !serviceOK(st) {
		t.Fatal("метка сервиса (через зеркало)")
	}
	st.Server.FromSub = false // свой сервер по ссылке
	if serviceOK(st) {
		t.Fatal("сервер не из подписки")
	}
	cfg, _ := buildConfig(st, t.TempDir(), nil)
	for _, o := range cfg["outbounds"].([]m) {
		if o["tag"] == "proxy" && o["type"] == "urltest" {
			t.Fatal("несколько путей для чужого сервера")
		}
	}
}

func TestSubNoticeAndLoginStatus(t *testing.T) {
	l, _ := parseLinks("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?type=tcp&security=none#%E2%9A%A0%20%D0%9B%D0%B8%D0%BC%D0%B8%D1%82")
	if n := subNotice(l); n != "⚠ Лимит" {
		t.Fatalf("%q", n)
	}
	l2, _ := parseLinks("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#a")
	if subNotice(l2) != "" {
		t.Fatal("обычная подписка")
	}
	if id := deviceID(); len(id) != 0 && len(id) != 32 {
		t.Fatalf("hwid %q", id)
	}
}

func TestPathsAcrossPortCopy(t *testing.T) {
	st := multiPathSettings()
	p443 := st.Profiles[3] // vless-2083
	p443.Name, p443.Port, p443.Host = "vless-2083 (443)", 443, "hoop.un1v249.ru"
	relay := st.Profiles[3]
	relay.Name, relay.Host = "vless-2083 (через Питер)", "198.51.100.30"
	st.Profiles = append(st.Profiles, p443, relay)
	st.Server = p443
	got := pathsFor(st)
	names := map[string]bool{}
	for _, p := range got {
		names[p.Name] = true
	}
	if !names["vless-2083 (через Питер)"] || !names["vless-2083"] || names["vlesska (через Питер)"] {
		t.Fatalf("%v", names)
	}
	if pathBase("vless-2083 (443) (через Питер)") != "vless-2083" {
		t.Fatal(pathBase("vless-2083 (443) (через Питер)"))
	}
}

func TestLinkTargetsAndProbe(t *testing.T) {
	st := multiPathSettings()
	got := linkTargets(st)
	labels := []string{}
	for _, x := range got {
		labels = append(labels, x.Label)
	}
	if strings.Join(labels, ",") != "напрямую,через Стокгольм,через Питер,интернет" {
		t.Fatal(labels)
	}
	st.SubURL = "https://other.example/sub" // чужая подписка: только сам сервер и интернет
	if n := len(linkTargets(st)); n != 2 {
		t.Fatal(n)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	if ms := tlsProbe(linkTarget{"x", "127.0.0.1", "example.com", port}); ms < 0 {
		t.Fatal("рукопожатие с живым сервером")
	}
	if ms := tlsProbe(linkTarget{"x", "127.0.0.1", "example.com", 1}); ms != -1 {
		t.Fatal("закрытый порт")
	}
	var l linkLog
	for i := 0; i < linkKeep+5; i++ {
		l.add(linkPoint{T: int64(i)})
	}
	if len(l.snapshot()) != linkKeep {
		t.Fatal(len(l.snapshot()))
	}
}

func TestHysteriaFallbackPath(t *testing.T) {
	st := multiPathSettings()
	hy := Server{Name: "hysteria2-57924", Type: "hysteria2", Host: "hoop.un1v249.ru", Port: 443, Password: "p", FromSub: true}
	hyR := hy
	hyR.Name, hyR.Host = "hysteria2-57924 (через Питер)", "198.51.100.30"
	foreign := Server{Name: "x", Type: "hysteria2", Host: "other.example", Port: 443, Password: "p", FromSub: true}
	st.Profiles = append(st.Profiles, hy, hyR, foreign)
	p := pathsFor(st)
	var hyN []string
	for _, x := range p {
		if x.Type == "hysteria2" {
			hyN = append(hyN, x.Name)
		}
	}
	if len(hyN) != 2 || hyN[0] != "hysteria2-57924" {
		t.Fatalf("%v", hyN)
	}
	if p[len(p)-1].Type != "hysteria2" || p[0].Type != "vless" {
		t.Fatal("запасной протокол должен идти после путей того же протокола")
	}
	cfg, err := buildConfig(st, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var group m
	for _, o := range cfg["outbounds"].([]m) {
		if o["tag"] == "proxy" {
			group = o
		}
	}
	if group == nil || len(group["outbounds"].([]string)) != 5 {
		t.Fatalf("%v", group)
	}
	st.Server.FromSub = false
	if len(protocolFallbacks(st, nil)) != 0 {
		t.Fatal("свой сервер — без запасного протокола")
	}
}

func TestFingerprintOverride(t *testing.T) {
	st := multiPathSettings()
	fps := func() map[string]string {
		cfg, err := buildConfig(st, t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, o := range cfg["outbounds"].([]m) {
			if tag := o["tag"].(string); strings.HasSuffix(tag, "-u1") || strings.HasSuffix(tag, "-u2") {
				continue
			}
			if tl, ok := o["tls"].(m); ok {
				if u, ok := tl["utls"].(m); ok {
					out[o["tag"].(string)] = u["fingerprint"].(string)
				}
			}
		}
		return out
	}
	for tag, fp := range fps() {
		if fp != "firefox" {
			t.Fatalf("авто для сервиса: %s=%s", tag, fp)
		}
	}
	st.TLSFingerprint = "link"
	for _, fp := range fps() {
		if fp != "chrome" {
			t.Fatalf("как в ссылке: %s", fp)
		}
	}
	st.TLSFingerprint = "edge"
	for _, fp := range fps() {
		if fp != "edge" {
			t.Fatal(fp)
		}
	}
	st.TLSFingerprint, st.SubURL = "auto", "https://other.example/s"
	if fpOverride(st) != "" {
		t.Fatal("чужая подписка — как в ссылке")
	}
}

func TestServiceHostBeatsBroaderDirectDomain(t *testing.T) {
	st := multiPathSettings()
	st.Services["discord"] = true
	st.DirectDomains = []string{"googleapis.com", "mirea.ru"}
	cfg, err := buildConfig(st, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyAt, directAt := -1, -1
	for i, r := range cfg["route"].(m)["rules"].([]m) {
		ds, _ := r["domain_suffix"].([]string)
		for _, d := range ds {
			if d == "discord-attachments-uploads-prd.storage.googleapis.com" && r["outbound"] == "proxy" && proxyAt < 0 {
				proxyAt = i
			}
			if d == "googleapis.com" && r["outbound"] == "direct" {
				directAt = i
			}
		}
	}
	if proxyAt < 0 || directAt < 0 || proxyAt > directAt {
		t.Fatalf("proxy=%d direct=%d", proxyAt, directAt)
	}
	if got := narrowerThan([]string{"a.b.com", "b.com", "xb.com"}, []string{"b.com"}); len(got) != 1 || got[0] != "a.b.com" {
		t.Fatal(got)
	}
}

func TestAllServerIPsDirect(t *testing.T) {
	st := multiPathSettings()
	for i := 0; i < 9; i++ { // больше 8 серверов: ретранслятор в конце списка раньше не попадал в «напрямую»
		p := st.Profiles[0]
		p.Name = fmt.Sprintf("x%d", i)
		p.Host = fmt.Sprintf("10.0.0.%d", i+1)
		st.Profiles = append([]Server{p}, st.Profiles...)
	}
	cfg, err := buildConfig(st, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(cfg["route"])
	for _, ip := range []string{"198.51.100.30/32", "198.51.100.20/32", "10.0.0.9/32"} {
		if !strings.Contains(string(b), ip) {
			t.Fatalf("%s not direct", ip)
		}
	}
}
