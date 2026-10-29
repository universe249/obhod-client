package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func adOnlySkip(st Settings) map[string]bool {
	skip := map[string]bool{}
	for _, tg := range neededTags(st) {
		if tg != adsTag {
			skip[tg] = true
		}
	}
	return skip
}

func TestAdBlockConfig(t *testing.T) {
	st := multiPathSettings()
	if strings.Contains(strings.Join(neededTags(st), ","), adsTag) {
		t.Fatal("ads list must be off by default")
	}
	st.AdBlock = true
	cfg, err := buildConfig(st, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(cfg)
	s := string(b)
	// список рекламы определён, по нему блокируем в DNS и в маршрутах, но он не попадает в «через сервер»
	if !strings.Contains(s, `"tag":"`+adsTag+`"`) || !strings.Contains(s, `"rcode":"NXDOMAIN"`) || !strings.Contains(s, `"action":"reject","rule_set":["`+adsTag+`"]`) {
		t.Fatalf("no ad rules: %s", s)
	}
	for _, r := range cfg["route"].(m)["rules"].([]m) {
		if r["outbound"] == "proxy" {
			if sets, ok := r["rule_set"].([]string); ok && strings.Contains(strings.Join(sets, ","), adsTag) {
				t.Fatal("ads list routed through the server")
			}
		}
	}
	// если список не скачался — правил нет, туннель всё равно запускается
	cfg, _ = buildConfig(st, t.TempDir(), map[string]bool{adsTag: true})
	b, _ = json.Marshal(cfg)
	if strings.Contains(string(b), adsTag) {
		t.Fatal("skipped ads list still referenced")
	}
}

// Настоящая проверка конфига ядром (если рядом лежит sing-box и скачанный список).
func TestAdBlockSingBoxCheck(t *testing.T) {
	dir := "/tmp/claude-0/adchk"
	if _, err := os.Stat(filepath.Join(dir, "rules", adsTag+".srs")); err != nil {
		t.Skip("нет списка рекламы для проверки")
	}
	defer adDNSPort.Store(0)
	for i, allow := range [][]string{nil, {"example.com"}} {
		adDNSPort.Store(int32(i * 19053)) // без счётчика и со счётчиком
		st := multiPathSettings()
		st.AdBlock, st.AdAllow = true, allow
		cfg, err := buildConfig(st, dir, adOnlySkip(st))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(cfg)
		if err := checkCoreConfig(b); err != nil {
			t.Fatalf("check %v: %v", allow, err)
		}
	}
}

func TestAdCounterDNS(t *testing.T) {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range []string{"an", "yandex", "ru"} {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	resp, name, ok := nxdomainReply(q)
	if !ok || name != "an.yandex.ru" || resp[0] != 0x12 || resp[1] != 0x34 || resp[3]&0x0f != 3 || resp[2]&0x80 == 0 || len(resp) != len(q) {
		t.Fatalf("%v %q %x", ok, name, resp)
	}
	if _, _, ok := nxdomainReply([]byte{1, 2, 3}); ok {
		t.Fatal("garbage accepted")
	}
	c := newAdCounter(t.TempDir())
	now := time.Now()
	c.add("an.yandex.ru.", now)
	c.add("an.yandex.ru", now.Add(time.Second)) // тот же запрос (A и AAAA) — один раз
	c.add("mc.yandex.ru", now.Add(2*time.Second))
	c.add("ads.example.co.uk", now.Add(3*time.Second))
	today, total, sites := c.view(now, 5)
	if today != 3 || total != 3 || sites[0].Site != "yandex.ru" || sites[0].N != 2 || sites[1].Site != "example.co.uk" {
		t.Fatalf("%d %d %+v", today, total, sites)
	}
	c.flush()
	c2 := newAdCounter(c.path[:len(c.path)-len("/adstats.json")])
	if td, tt, _ := c2.view(now, 5); td != 3 || tt != 3 {
		t.Fatal("not persisted")
	}
	// конфиг: при работающем счётчике реклама уходит в него
	adDNSPort.Store(19053)
	defer adDNSPort.Store(0)
	st := multiPathSettings()
	st.AdBlock = true
	cfg, _ := buildConfig(st, t.TempDir(), nil)
	b, _ := json.Marshal(cfg)
	if !strings.Contains(string(b), `"server":"dns-ads"`) || !strings.Contains(string(b), `"server_port":19053`) {
		t.Fatal("ads not sent to counter")
	}
}

// Вживую: настоящий sing-box спрашивает наш DNS-сервер счётчика, клиент получает «нет такого имени», счётчик растёт.
func TestAdCounterWithSingBox(t *testing.T) {
	dir := "/tmp/claude-0/adchk"
	if _, err := os.Stat(filepath.Join(dir, "rules", adsTag+".srs")); err != nil {
		t.Skip("нет списка рекламы")
	}
	adDir, _ := os.MkdirTemp("", "adcnt") // счётчик дописывает файл в фоне уже после теста — t.TempDir тут спотыкается
	defer os.RemoveAll(adDir)
	a := &App{quit: make(chan struct{}), ads: newAdCounter(adDir), st: defaultSettings()}
	defer close(a.quit)
	a.startAdDNS()
	defer adDNSPort.Store(0)
	p := adDNSPort.Load()
	cfg := fmt.Sprintf(`{"log":{"level":"warn"},
 "dns":{"servers":[{"type":"udp","tag":"up","server":"127.0.0.1","server_port":9},{"type":"udp","tag":"dns-ads","server":"127.0.0.1","server_port":%d}],
   "rules":[{"rule_set":["%s"],"server":"dns-ads"}]},
 "inbounds":[{"type":"direct","tag":"dns-in","listen":"127.0.0.1","listen_port":15354,"network":"udp"}],
 "outbounds":[{"type":"direct","tag":"direct"}],
 "route":{"rule_set":[{"tag":"%s","type":"local","format":"binary","path":"%s"}],
   "rules":[{"action":"sniff"},{"inbound":"dns-in","action":"hijack-dns"}],"default_domain_resolver":"up"}}`, p, adsTag, adsTag, filepath.Join(dir, "rules", adsTag+".srs"))
	core, err := runCoreInProcess([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	time.Sleep(500 * time.Millisecond)
	conn, err := net.Dial("udp", "127.0.0.1:15354")
	if err != nil {
		t.Fatal(err)
	}
	q := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 2, 'm', 'c', 6, 'y', 'a', 'n', 'd', 'e', 'x', 2, 'r', 'u', 0, 0, 1, 0, 1}
	buf := make([]byte, 512)
	var n int
	for try := 0; try < 6; try++ { // ядру под нагрузкой (весь набор тестов) нужно чуть больше времени на старт
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write(q)
		if n, err = conn.Read(buf); err == nil {
			break
		}
	}
	if err != nil || n < 4 || buf[3]&0x0f != 3 {
		t.Fatalf("ответ %v %x", err, buf[:n])
	}
	if today, _, _ := a.ads.view(time.Now(), 5); today != 1 {
		t.Fatalf("счётчик %d", today)
	}
}

func TestSuspectTracker(t *testing.T) {
	tr := newSuspectTracker()
	t0 := time.Now()
	conn := func(id, host string, up, down int64, age time.Duration, now time.Time) connObs {
		return connObs{ID: id, Host: host, Port: "443", Direct: true, Up: up, Down: down, Started: now.Add(-age)}
	}
	// три зависших соединения к blocked.example.com (ClientHello ушёл, ответа нет) — подсказка один раз
	var got []string
	for i, id := range []string{"a", "b", "c"} {
		now := t0.Add(time.Duration(i) * time.Minute)
		got = append(got, tr.observe(now, []connObs{conn(id, "www.blocked.example.com", 517, 0, 10*time.Second, now)})...)
	}
	if len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("stall: %v", got)
	}
	// сброшенные соединения: видели без ответа, потом пропали
	now := t0
	at := func(s int) time.Time { return now.Add(time.Duration(s) * time.Second) }
	tr.observe(at(0), []connObs{conn("r1", "cdn.reset.org", 600, 0, time.Second, at(0))})
	tr.observe(at(5), nil)
	tr.observe(at(10), []connObs{conn("r2", "cdn.reset.org", 600, 0, time.Second, at(10))})
	tr.observe(at(15), nil)
	if l := tr.list(at(16), func(string) bool { return false }); len(l) != 1 || l[0].Site != "example.com" {
		t.Fatalf("2 resets is not enough: %+v", l)
	}
	tr.observe(at(20), []connObs{conn("r3", "cdn.reset.org", 600, 0, time.Second, at(20))})
	fresh := tr.observe(at(25), nil)
	if len(fresh) != 1 || fresh[0] != "reset.org" {
		t.Fatalf("reset: %v", fresh)
	}
	// сайт, который работает (пришло много данных), не подозреваем, даже если были обрывы
	for i, id := range []string{"w1", "w2", "w3"} {
		now := t0.Add(time.Duration(i) * time.Minute)
		tr.observe(now, []connObs{conn(id, "slow.works.net", 517, 0, 10*time.Second, now), conn("ok"+id, "works.net", 900, 300<<10, time.Minute, now)})
	}
	for _, s := range tr.list(t0.Add(3*time.Minute), func(string) bool { return false }) {
		if s.Site == "works.net" {
			t.Fatal("working site suspected")
		}
	}
	// через сервер, по голому IP и не 443 — не оцениваем
	for i := 0; i < 5; i++ {
		c := conn("p"+itoa(i), "x.proxied.com", 517, 0, time.Minute, t0)
		c.Direct = false
		ip := conn("i"+itoa(i), "1.2.3.4", 517, 0, time.Minute, t0)
		tr.observe(t0, []connObs{c, ip})
	}
	// скрытые и уже добавленные — не показываем
	st := defaultSettings()
	st.SuggestIgnore = []string{"reset.org"}
	st.CustomDomains = []string{"example.com"}
	if l := tr.list(t0.Add(time.Minute), suspectSkip(st)); len(l) != 0 {
		t.Fatalf("skip: %+v", l)
	}
	if siteOf("an.yandex.ru") != "yandex.ru" || siteOf("a.b.example.co.uk") != "example.co.uk" {
		t.Fatal("siteOf")
	}
}

func TestRadar(t *testing.T) {
	var r radar
	t0 := time.Now()
	ok := map[string]int{pathDirect: 150, "через Питер": 70, "через Стокгольм": 110, pathInternet: 20}
	blocked := map[string]int{pathDirect: 5003, "через Питер": 5002, "через Стокгольм": 112, pathInternet: 18}
	if _, send := r.step(ok, t0); send {
		t.Fatal("ok at start must not be reported")
	}
	var sent []radarState
	for i := 1; i <= 8; i++ { // прямой путь и Питер молчат 8 минут
		if rs, send := r.step(blocked, t0.Add(time.Duration(i)*time.Minute)); send {
			sent = append(sent, rs)
			r.markSent(rs.State, t0.Add(time.Duration(i)*time.Minute))
		}
	}
	if len(sent) != 1 || sent[0].State != "main" || len(sent[0].Via) != 1 || sent[0].Via[0] != "через Стокгольм" {
		t.Fatalf("blocked: %+v", sent)
	}
	// нет интернета — ничего не решаем
	if _, send := r.step(map[string]int{pathDirect: -1, pathInternet: -1}, t0.Add(9*time.Minute)); send {
		t.Fatal("no internet must not be reported")
	}
	// через 30 минут — повтор, пока блокировка держится
	if rs, send := r.step(blocked, t0.Add(40*time.Minute)); !send || rs.State != "main" {
		t.Fatal("refresh")
	}
	r.markSent("main", t0.Add(40*time.Minute))
	// всё вернулось — сообщаем один раз
	rs, send := r.step(ok, t0.Add(41*time.Minute))
	if !send || rs.State != "ok" {
		t.Fatal("recovered")
	}
	r.markSent("ok", t0.Add(41*time.Minute))
	if _, send := r.step(ok, t0.Add(42*time.Minute)); send {
		t.Fatal("ok twice")
	}
	// ни один путь не работает, интернет есть
	var r2 radar
	all := map[string]int{pathDirect: -1, "через Питер": -1, pathInternet: 20}
	for i := 0; i <= 5; i++ {
		rs, send = r2.step(all, t0.Add(time.Duration(i)*time.Minute))
	}
	if !send || rs.State != "all" {
		t.Fatalf("all: %+v %v", rs, send)
	}
}
