package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseHop(t *testing.T) {
	cases := []struct {
		line string
		want Hop
		ok   bool
	}{
		{"  1    <1 ms    <1 ms    <1 ms  192.168.1.1", Hop{1, "192.168.1.1", 1}, true},
		{"  2    12 ms    14 ms    16 ms  10.20.30.1", Hop{2, "10.20.30.1", 14}, true},
		{"  3     *        *        *     Превышен интервал ожидания для запроса.", Hop{3, "", -1}, true},
		{" 4  93.158.134.3  5.2 ms  5.1 ms  5.3 ms", Hop{4, "93.158.134.3", 5}, true},
		{"Трассировка маршрута к 203.0.113.10 с максимальным числом прыжков 18", Hop{}, false},
		{"Трассировка завершена.", Hop{}, false},
	}
	for _, c := range cases {
		got, ok := parseHop(c.line)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%q: got %+v %v, want %+v %v", c.line, got, ok, c.want, c.ok)
		}
	}
}

func TestTraceVerdict(t *testing.T) {
	hops := []Hop{{1, "192.168.1.1", 1}, {2, "10.0.0.1", 5}, {3, "", -1}, {4, "", -1}}
	lv, tx := traceVerdict(hops, "1.2.3.4", true, true, 40, 8443)
	if lv != "ok" || !strings.Contains(tx, "8443") || !strings.Contains(tx, "ICMP") {
		t.Fatalf("tcp ok: %s %s", lv, tx)
	}
	lv, tx = traceVerdict(hops, "1.2.3.4", true, false, 0, 8443)
	if lv != "bad" || !strings.Contains(tx, "№2") || !strings.Contains(tx, "рядом с тобой") {
		t.Fatalf("dead at hop 2: %s %s", lv, tx)
	}
	far := []Hop{{1, "a", 1}, {2, "b", 1}, {3, "c", 1}, {4, "d", 1}, {5, "e", 9}, {6, "", -1}}
	hops2 := []Hop{}
	for i, h := range far {
		if h.IP != "" {
			h.IP = "10.0.0." + string(rune('1'+i))
		}
		hops2 = append(hops2, h)
	}
	_, tx = traceVerdict(hops2, "1.2.3.4", true, false, 0, 443)
	if !strings.Contains(tx, "у хостера") {
		t.Fatalf("far hop: %s", tx)
	}
	lv, _ = traceVerdict([]Hop{{1, "", -1}}, "1.2.3.4", false, false, 0, 0)
	if lv != "bad" {
		t.Fatal("silent first hop must be bad")
	}
	lv, _ = traceVerdict([]Hop{{1, "1.2.3.4", 5}}, "1.2.3.4", false, false, 0, 0)
	if lv != "ok" {
		t.Fatal("reached target must be ok")
	}
}

func TestParseDomainList(t *testing.T) {
	text := "\xef\xbb\xbf# comment\nexample.com\n*.Sub.Example.org\ndomain:v2ray.net\nfull:full.example.io\n||adblock.example^\n0.0.0.0 hosts.example\n127.0.0.1 localhost\n192.168.1.1\nkeyword:foo\nnot a domain here\nexample.com\nxn--e1afmkfd.xn--p1ai # trailing comment\n"
	got, err := parseDomainList(text)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "sub.example.org", "v2ray.net", "full.example.io", "adblock.example", "hosts.example", "xn--e1afmkfd.xn--p1ai"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
	js, err := parseDomainList(`{"version":2,"rules":[{"domain":["a.example"],"domain_suffix":["b.example",".c.example"]}]}`)
	if err != nil || strings.Join(js, ",") != "a.example,b.example,c.example" {
		t.Fatalf("json: %v %v", js, err)
	}
	if _, err := parseDomainList("SRS\x01\x02"); err == nil {
		t.Fatal(".srs must be refused")
	}
	if _, err := parseDomainList("# nothing\n\n"); err == nil {
		t.Fatal("empty list must be refused")
	}
	if _, err := validListURL("ftp://x/y"); err == nil {
		t.Fatal("ftp must be refused")
	}
}

func TestCustomListsFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			http.Error(w, "no", 500)
			return
		}
		w.Write([]byte("tracker.example\nads.example\n"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	a := &App{dataDir: dir, quit: make(chan struct{})}
	a.st = defaultSettings()
	a.st.CustomDomains = []string{"manual.example"}
	a.st.Server = Server{Type: "hysteria2", Host: "1.2.3.4", Port: 443, Password: "x"}
	post := func(body string) (int, map[string]any) {
		rr := httptest.NewRecorder()
		a.handleLists(rr, httptest.NewRequest("POST", "/api/lists", strings.NewReader(body)))
		var m map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &m)
		return rr.Code, m
	}
	if code, m := post(`{"action":"add","url":"` + srv.URL + `/bad"}`); code != 400 || !strings.Contains(m["error"].(string), "500") {
		t.Fatalf("bad url must fail: %d %v", code, m)
	}
	if code, m := post(`{"action":"add","url":"` + srv.URL + `/list","name":"Реклама","mode":"direct"}`); code != 200 {
		t.Fatalf("add: %d %v", code, m)
	}
	if code, _ := post(`{"action":"add","url":"` + srv.URL + `/list"}`); code != 400 {
		t.Fatal("duplicate must fail")
	}
	st := a.settings()
	if len(st.CustomLists) != 1 || st.CustomLists[0].Count != 2 || st.CustomLists[0].Mode != "direct" {
		t.Fatalf("lists: %+v", st.CustomLists)
	}
	got := withCustomLists(st, dir)
	if strings.Join(got.DirectDomains, ",") != "tracker.example,ads.example" || strings.Join(got.CustomDomains, ",") != "manual.example" {
		t.Fatalf("merge: direct=%v proxy=%v", got.DirectDomains, got.CustomDomains)
	}
	if len(st.DirectDomains) != 0 {
		t.Fatal("withCustomLists must not touch the caller's slices")
	}
	post(`{"action":"mode","index":0,"mode":"proxy"}`)
	got = withCustomLists(a.settings(), dir)
	if len(got.CustomDomains) != 3 || len(got.DirectDomains) != 0 {
		t.Fatalf("after mode switch: %v %v", got.CustomDomains, got.DirectDomains)
	}
	// the list reaches the sing-box config
	cfg, err := buildConfig(a.settings(), dir, map[string]bool{"ru-blocked-domains": true, "ru-blocked-ip": true})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(cfg)
	if !strings.Contains(string(b), "tracker.example") {
		t.Fatal("list domains missing from config")
	}
	post(`{"action":"delete","index":0}`)
	if len(a.settings().CustomLists) != 0 {
		t.Fatal("delete failed")
	}
	if _, err := os.Stat(listFile(dir, srv.URL+"/list")); err == nil {
		t.Fatal("list file must be removed")
	}
}

func TestAutoGame(t *testing.T) {
	now := time.Now()
	if autoGameAction(true, false, false, time.Time{}, now) != "on" {
		t.Fatal("game started: on")
	}
	if autoGameAction(true, true, true, time.Time{}, now) != "" {
		t.Fatal("already on")
	}
	if autoGameAction(false, true, true, now.Add(-30*time.Second), now) != "" {
		t.Fatal("closed 30s ago: wait")
	}
	if autoGameAction(false, true, true, now.Add(-2*time.Minute), now) != "off" {
		t.Fatal("closed 2 min ago: off")
	}
	if autoGameAction(false, true, false, now.Add(-time.Hour), now) != "" {
		t.Fatal("manual game mode must stay")
	}
	if !anyRunning([]string{"Chrome.exe", "Dota2.exe"}, []string{`C:\Games\dota2.exe`}) || anyRunning([]string{"a.exe"}, []string{"b.exe"}) {
		t.Fatal("anyRunning")
	}
}

func TestDNSPickAndStub(t *testing.T) {
	rs := []DNSResult{
		{Name: "sys", Kind: "system", OK: 6, Total: 6, Ms: 5},
		{Name: "fast but fake", Kind: "udp", OK: 6, Total: 6, Ms: 8, Stub: 1},
		{Name: "partial", Kind: "udp", OK: 4, Total: 6, Ms: 3},
		{Name: "good", Kind: "udp", OK: 6, Total: 6, Ms: 20},
		{Name: "better", Kind: "doh", OK: 6, Total: 6, Ms: 12},
	}
	if i := dnsPick(rs); i != 4 {
		t.Fatalf("pick = %d", i)
	}
	if dnsPick(rs[:3]) != -1 {
		t.Fatal("nothing suitable must give -1")
	}
	for _, s := range []string{"0.0.0.0", "127.0.0.1", "10.1.2.3", "192.168.0.9", "169.254.1.1"} {
		if !isStubIP(net.ParseIP(s)) {
			t.Errorf("%s must be a stub", s)
		}
	}
	if isStubIP(net.ParseIP("93.184.216.34")) {
		t.Error("public address is not a stub")
	}
	if !strings.Contains(dnsAdvice(append(rs, DNSResult{})), "better") && !strings.Contains(dnsAdvice(rs), "better") {
		t.Error("advice must name the best resolver")
	}
}

func TestSpeedMeter(t *testing.T) {
	var m speedMeter
	t0 := time.Unix(1000, 0)
	if _, _, ok := m.rates(100, 1000, t0); ok {
		t.Fatal("first reading has no rate")
	}
	ru, rd, ok := m.rates(300, 3000, t0.Add(2*time.Second))
	if !ok || ru != 100 || rd != 1000 {
		t.Fatalf("rates: %v %v %v", ru, rd, ok)
	}
	if _, _, ok := m.rates(10, 10, t0.Add(4*time.Second)); ok {
		t.Fatal("counter reset must not give a negative rate")
	}
	if fmtRate(1500000) != "1.4 МБ/с" || fmtRate(2048) != "2 КБ/с" || fmtRate(12) != "12 Б/с" {
		t.Fatalf("fmtRate: %s %s %s", fmtRate(1500000), fmtRate(2048), fmtRate(12))
	}
}
