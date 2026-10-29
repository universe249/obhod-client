package main

import (
	"errors"
	"testing"
)

func TestHostOverrideKeepsNames(t *testing.T) {
	old := lookupHostFn
	defer func() { lookupHostFn = old }()
	hostIPs = &hostIPCache{known: map[string]string{}, override: map[string]string{}}
	dir := t.TempDir()
	st := multiSettings()
	st.Server = Server{Type: "vless", Host: "hoop.example.ru", Port: 443, Security: "reality", UUID: "u"}

	lookupHostFn = func(string) ([]string, error) { return []string{"2001:db8::1", "203.0.113.7"}, nil }
	hostIPs.refresh(dir, st)
	if hostIPs.known["hoop.example.ru"] != "203.0.113.7" {
		t.Fatal(hostIPs.known)
	}
	if applyHostOverride(st.Server).Host != "hoop.example.ru" {
		t.Fatal("при рабочем DNS адрес менять нельзя")
	}

	lookupHostFn = func(string) ([]string, error) { return nil, errors.New("no such host") }
	hostIPs.refresh(dir, st)
	s := applyHostOverride(st.Server)
	if s.Host != "203.0.113.7" || s.SNI != "hoop.example.ru" || s.WSHost != "hoop.example.ru" {
		t.Fatalf("%+v", s)
	}
	o, err := outboundBase(st.Server, 0)
	if err != nil || o["server"] != "203.0.113.7" {
		t.Fatalf("%v %v", o, err)
	}

	// после перезапуска программы запомненный адрес читается с диска
	hostIPs = &hostIPCache{known: map[string]string{}, override: map[string]string{}}
	hostIPs.load(dir)
	hostIPs.refresh(dir, st)
	if applyHostOverride(st.Server).Host != "203.0.113.7" {
		t.Fatal("кэш с диска не использован")
	}

	// DNS вернулся: подмена снимается
	lookupHostFn = func(string) ([]string, error) { return []string{"203.0.113.9"}, nil }
	hostIPs.refresh(dir, st)
	if applyHostOverride(st.Server).Host != "hoop.example.ru" || hostIPs.known["hoop.example.ru"] != "203.0.113.9" {
		t.Fatal("подмена не снята")
	}

	// сервер с IP не трогаем; неизвестный домен без кэша тоже
	if got := applyHostOverride(Server{Host: "198.51.100.1"}); got.Host != "198.51.100.1" {
		t.Fatal(got)
	}
}

func TestNetVerdict(t *testing.T) {
	if _, ok := verdictFor(true, true, true); ok {
		t.Fatal("сервер доступен: подсказка не нужна")
	}
	for _, c := range []struct {
		i, d, s bool
		want    string
	}{{false, false, false, "Нет интернета"}, {true, false, false, "DNS"}, {true, true, false, "сервер недоступен"}} {
		v, ok := verdictFor(c.i, c.d, c.s)
		if !ok || !contains(v.Title, c.want) {
			t.Fatalf("%v: %q", c, v.Title)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestSrvHistory(t *testing.T) {
	s := &srvStats{M: map[string]*srvCell{}}
	p := Server{Type: "vless", Host: "a.example", Port: 443, Name: "A"}
	id := srvID(p)
	s.M["n1/2/"+id] = &srvCell{OK: 8, Fail: 2, Ms: 800}
	s.M["n2/2/"+id] = &srvCell{OK: 2, Fail: 0, Ms: 400}
	rows := s.history([]Server{p}, p)
	c := rows[0].B[2]
	if c.N != 12 || c.OK != 83 || c.Ms != 120 || !rows[0].Current {
		t.Fatalf("bad %+v", rows[0])
	}
	if rows[0].B[0].OK != -1 {
		t.Fatal("empty bucket must be -1")
	}
}

func TestPendingLinkTakenOnce(t *testing.T) {
	a := &App{pending: "https://x.example/sub/a"}
	if a.pendingLink() != "https://x.example/sub/a" {
		t.Fatal("first call must return link")
	}
	if a.pendingLink() != "" {
		t.Fatal("second call must be empty")
	}
}

func TestTransientExecErr(t *testing.T) {
	if !transientExecErr("fork/exec C:\\singbox\\sing-box.exe: Access is denied.") || transientExecErr("unknown field") {
		t.Fatal("bad classification")
	}
}
