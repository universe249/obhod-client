package main

import (
	"strings"
	"testing"
	"time"
)

func TestNetSnapshot(t *testing.T) {
	ifs := []ifaceInfo{
		{Name: "Ethernet", Up: true, Addrs: []string{"192.168.1.10", "fe80::1"}},
		{Name: "lo", Up: true, Loopback: true, Addrs: []string{"127.0.0.1"}},
		{Name: "Wi-Fi", Up: false, Addrs: []string{"10.0.0.5"}},
		{Name: "sing-tun", Up: true, Addrs: []string{"172.19.0.1"}},
		{Name: "Bluetooth", Up: true, Addrs: []string{"169.254.3.4"}},
	}
	sig, key := netSnapshot(ifs)
	if sig != "Ethernet|192.168.1.10" || key == "" {
		t.Fatalf("%q %q", sig, key)
	}
	// тот же дом, другой адрес из той же подсети: сигнатура меняется, ключ сети нет
	ifs[0].Addrs = []string{"192.168.1.77"}
	sig2, key2 := netSnapshot(ifs)
	if sig2 == sig || key2 != key {
		t.Fatalf("%q %q", sig2, key2)
	}
	if s, k := netSnapshot(nil); s != "" || k != "" {
		t.Fatal("пустая сеть")
	}
}

func TestNetTracker(t *testing.T) {
	var tr netTracker
	t0 := time.Unix(1000, 0)
	at := func(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }
	steps := []struct {
		sig  string
		sec  int
		want bool
	}{
		{"A", 0, false},  // первое чтение
		{"A", 4, false},  // принято, но это первое
		{"B", 10, false}, // сменилось, ещё не устоялось
		{"B", 12, false},
		{"B", 14, true}, // устоялось 4 с
		{"B", 20, false},
		{"C", 21, false},
		{"C", 26, false}, // меньше 20 с после прошлой реакции
		{"", 30, false},  // сети нет
		{"", 35, false},  // обрыв не повод перезапускать
		{"C", 36, false},
		{"C", 41, true}, // сеть вернулась: переподключаемся
	}
	for i, s := range steps {
		if got := tr.step(s.sig, at(s.sec)); got != s.want {
			t.Fatalf("шаг %d (%q на %d с): %v, ожидали %v", i, s.sig, s.sec, got, s.want)
		}
	}
}

func TestSrvStatsBestAndOrder(t *testing.T) {
	a := Server{Type: "vless", Host: "a", Port: 443}
	b := Server{Type: "hysteria2", Host: "b", Port: 443}
	c := Server{Type: "trojan", Host: "c", Port: 443}
	list := []Server{a, b, c}
	s := newSrvStats(t.TempDir())
	for i := 0; i < 20; i++ {
		s.record("net1", 2, srvID(a), i%4 != 0, 50) // 75%
		s.record("net1", 2, srvID(b), true, 30)     // 100%
	}
	if i, ok := s.best(list, a, "net1", 2); !ok || i != 1 {
		t.Fatalf("%d %v", i, ok)
	}
	if _, ok := s.best(list, b, "net1", 2); ok {
		t.Fatal("лучший уже выбран")
	}
	if _, ok := s.best(list, a, "net2", 2); ok { // в другой сети данных нет
		t.Fatal("нет данных")
	}
	if _, ok := s.best(list, a, "net1", 0); ok { // в другое время суток тоже
		t.Fatal("нет данных за это время")
	}
	ord := s.order(list, a, "net1", 2)
	if len(ord) != 2 || ord[0] != 1 || ord[1] != 2 {
		t.Fatalf("%v", ord)
	}
	// сохранение и загрузка
	s.flush()
	s2 := newSrvStats(s.path[:len(s.path)-len("/srvstats.json")])
	if sc, n := s2.score("net1", 2, srvID(b)); n != 20 || sc < 0.9 {
		t.Fatalf("%v %d", sc, n)
	}
	var nilS *srvStats
	nilS.record("n", 0, "x", true, 1)
	if _, n := nilS.score("n", 0, "x"); n != 0 {
		t.Fatal("nil")
	}
}

func TestParseHotkey(t *testing.T) {
	ok := map[string]string{"ctrl+alt+o": "Ctrl+Alt+O", "Alt+F10": "Alt+F10", "shift+ctrl+space": "Ctrl+Shift+Space", "win+1": "Win+1", "Ctrl+Alt+PageUp": "Ctrl+Alt+Pageup", "": ""}
	for in, want := range ok {
		_, _, got, err := parseHotkey(in)
		if err != nil || got != want {
			t.Errorf("%q -> %q (%v), want %q", in, got, err, want)
		}
	}
	m, vk, _, _ := parseHotkey("Ctrl+Alt+O")
	if m != modCtrl|modAlt || vk != 'O' {
		t.Fatal(m, vk)
	}
	if _, vk, _, _ := parseHotkey("Alt+F5"); vk != 0x74 {
		t.Fatal(vk)
	}
	for _, bad := range []string{"O", "Ctrl+O", "Shift+A", "Ctrl+Alt", "Ctrl+Alt+Delete", "Ctrl+Alt+Q+W", "Alt+F25", "Alt+Ё", "Alt++"} {
		if _, _, _, err := parseHotkey(bad); err == nil {
			t.Errorf("%q должно быть отклонено", bad)
		}
	}
	if _, err := cleanHotkeys(map[string]string{"toggle": "Ctrl+Alt+O", "game": "alt+ctrl+o"}); err == nil {
		t.Error("дубликат должен отклоняться")
	}
	c, err := cleanHotkeys(map[string]string{"toggle": "ctrl+alt+x"})
	if err != nil || c["toggle"] != "Ctrl+Alt+X" || c["game"] != "" {
		t.Fatalf("%v %v", c, err)
	}
}

func TestSchedule(t *testing.T) {
	rules := cleanSchedule([]SchedRule{
		{Days: []int{1, 2, 3, 4, 5}, Time: "9:05", Action: "preset", Preset: "b:global"},
		{Time: "23:30", Action: "off"},
		{Time: "25:00", Action: "off"},    // неверное время
		{Time: "10:00", Action: "reboot"}, // неверное действие
		{Time: "10:00", Action: "preset"}, // нет набора
		{Days: []int{0, 1, 2, 3, 4, 5, 6, 9}, Time: "07:00", Action: "on", Preset: "x"},
	})
	if len(rules) != 3 || rules[0].Time != "09:05" || rules[2].Days != nil || rules[2].Preset != "" {
		t.Fatalf("%+v", rules)
	}
	loc := time.UTC
	mon := time.Date(2026, 10, 12, 9, 4, 30, 0, loc) // понедельник
	if d := schedDue(rules, mon, mon.Add(40*time.Second)); len(d) != 1 || d[0] != 0 {
		t.Fatalf("%v", d)
	}
	if d := schedDue(rules, mon.Add(40*time.Second), mon.Add(70*time.Second)); len(d) != 0 {
		t.Fatalf("повторно не должно срабатывать: %v", d)
	}
	sun := time.Date(2026, 10, 11, 9, 4, 30, 0, loc) // воскресенье: правило только по будням
	if d := schedDue(rules, sun, sun.Add(2*time.Minute)); len(d) != 0 {
		t.Fatalf("%v", d)
	}
	// опоздавший цикл: окно в несколько минут не теряет правило
	if d := schedDue(rules, time.Date(2026, 10, 12, 23, 20, 0, 0, loc), time.Date(2026, 10, 12, 23, 33, 0, 0, loc)); len(d) != 1 || d[0] != 1 {
		t.Fatalf("%v", d)
	}
	if len(cleanSchedule(make([]SchedRule, 0))) != 0 {
		t.Fatal()
	}
}

func TestServerLinkRoundTrip(t *testing.T) {
	list := []Server{
		{Name: "Хай 2", Type: "hysteria2", Host: "a.example.com", Port: 8443, SNI: "x.com", Password: "p@ss:w/rd", ObfsPassword: "ob", Insecure: true, HopPorts: "20000-30000"},
		{Name: "Reality", Type: "vless", Host: "1.2.3.4", Port: 443, UUID: "11111111-2222-3333-4444-555555555555", Flow: "xtls-rprx-vision", Security: "reality", SNI: "ya.ru", Fingerprint: "chrome", PublicKey: "PBK_key-1", ShortID: "ab12", Spx: "/", Network: "tcp"},
		{Name: "WS", Type: "vless", Host: "h.io", Port: 443, UUID: "u", Security: "tls", SNI: "h.io", Network: "ws", WSPath: "/p?x=1", WSHost: "h.io"},
		{Name: "XH", Type: "vless", Host: "h.io", Port: 443, UUID: "u", Security: "tls", Network: "xhttp", WSPath: "/x", XMode: "auto", XExtra: `{"a":1}`},
		{Name: "Тр", Type: "trojan", Host: "t.io", Port: 443, Password: "pw", Security: "tls", SNI: "t.io", Network: "tcp"},
		{Name: "SS", Type: "shadowsocks", Host: "s.io", Port: 8388, Method: "aes-256-gcm", Password: "a:b@c"},
	}
	for _, s := range list {
		l := serverLink(s)
		got, err := parseLink(l)
		if err != nil {
			t.Fatalf("%s: %v (%s)", s.Name, err, l)
		}
		if got != s {
			t.Fatalf("%s: не совпало\n%+v\n%+v\n%s", s.Name, s, got, l)
		}
	}
}

func TestPresetCode(t *testing.T) {
	p := Preset{Name: "Игры", Mode: "global", Services: map[string]bool{"youtube": true, "x": false}, GameMode: true, ProxyApps: []string{"a.exe", "A.exe", " "}, DirectApps: []string{"b.exe"}}
	c, err := presetCode(p)
	if err != nil || !strings.HasPrefix(c, "OBH1:") {
		t.Fatal(err, c)
	}
	g, err := parsePresetCode(" " + c + "\n")
	if err != nil || g.Name != "Игры" || g.Mode != "global" || !g.Services["youtube"] || g.Services["x"] || len(g.ProxyApps) != 1 || !g.GameMode {
		t.Fatalf("%v %+v", err, g)
	}
	for _, bad := range []string{"", "hello", "OBH1:!!!", "OBH1:aGVsbG8"} {
		if _, err := parsePresetCode(bad); err == nil {
			t.Fatal("ожидалась ошибка для", bad)
		}
	}
}
