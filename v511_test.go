package main

import "testing"

func TestAltFingerprints(t *testing.T) {
	r := Server{Type: "vless", Security: "reality", Host: "h", Port: 443, UUID: "u"}
	alt := altFingerprints(r)
	if len(alt) != 2 || alt[0] != "firefox" || alt[1] != "safari" {
		t.Fatalf("reality default chrome: got %v", alt)
	}
	r.Fingerprint = "firefox"
	alt = altFingerprints(r)
	if len(alt) != 2 || alt[0] != "chrome" || alt[1] != "safari" {
		t.Fatalf("firefox: got %v", alt)
	}
	if altFingerprints(Server{Type: "hysteria2"}) != nil {
		t.Fatal("hysteria2 has no uTLS")
	}
	if altFingerprints(Server{Type: "vless", Security: "none"}) != nil {
		t.Fatal("no tls, no fingerprint")
	}
}

func TestFingerprintExits(t *testing.T) {
	st := defaultSettings()
	st.Server = Server{Type: "vless", Security: "reality", Host: "a.example", Port: 443, UUID: "u1", PublicKey: "k", ShortID: "s", SNI: "x.com"}
	ex := serverExits(st, allServers(st))
	got := map[string]string{}
	for _, e := range ex {
		if e.Kind == kindFP1 || e.Kind == kindFP2 {
			u, _ := e.Out["tls"].(m)["utls"].(m)
			got[e.Kind], _ = u["fingerprint"].(string)
		}
	}
	if got[kindFP1] != "firefox" || got[kindFP2] != "safari" {
		t.Fatalf("exits: %v", got)
	}
	c := tuneCandidates(st)
	n := 0
	for _, x := range c {
		if x.Kind == kindFP1 || x.Kind == kindFP2 {
			n++
			if x.Way == "как сохранён" {
				t.Fatal("way label missing")
			}
		}
	}
	if n != 0 && n != 2 { // base exit only exists with several servers; the candidate list follows the exits
		t.Fatalf("candidates: %d", n)
	}
}

type tErr struct{ msg string }

func (e tErr) Error() string { return e.msg }

func okProbe() linkProbe {
	return linkProbe{
		DNS:    func(string) ([]string, error) { return []string{"1.2.3.4"}, nil },
		TCP:    func(string) error { return nil },
		TLS:    func(string, string) error { return nil },
		Tunnel: func() (int, error) { return 120, nil },
	}
}

func TestLinkDiagVerdicts(t *testing.T) {
	sv := Server{Type: "vless", Security: "reality", Host: "hoop.example.ru", Port: 443, SNI: "x.com"}

	if r := runLinkDiag(sv, true, okProbe()); r.Level != "ok" || len(r.Steps) != 4 {
		t.Fatalf("ok: %+v", r)
	}
	if r := runLinkDiag(sv, false, okProbe()); r.Level != "warn" {
		t.Fatalf("tunnel off: %+v", r)
	}
	p := okProbe()
	p.DNS = func(string) ([]string, error) { return nil, tErr{"no such host"} }
	if r := runLinkDiag(sv, true, p); r.Level != "bad" || len(r.Steps) != 1 {
		t.Fatalf("dns: %+v", r)
	}
	p = okProbe()
	p.TCP = func(string) error { return tErr{"connection refused"} }
	p.Tunnel = func() (int, error) { return 0, tErr{"timeout"} }
	r := runLinkDiag(sv, true, p)
	if r.Level != "bad" || r.Steps[1].Info != "порт закрыт" {
		t.Fatalf("tcp: %+v", r)
	}
	if r2 := runLinkDiag(sv, true, func() linkProbe { q := okProbe(); q.TCP = p.TCP; return q }()); r2.Level != "warn" {
		t.Fatalf("tcp closed but tunnel works: %+v", r2)
	}
	p = okProbe()
	p.TLS = func(string, string) error { return tErr{"read: connection reset by peer"} }
	p.Tunnel = func() (int, error) { return 0, tErr{"timeout"} }
	if r := runLinkDiag(sv, true, p); r.Level != "bad" || r.Verdict != "Порт открыт, но защищённое соединение не устанавливается." {
		t.Fatalf("tls: %+v", r)
	}
	p = okProbe()
	p.Tunnel = func() (int, error) { return 0, tErr{"timeout"} }
	if r := runLinkDiag(sv, true, p); r.Level != "bad" || len(r.Steps) != 4 {
		t.Fatalf("tunnel: %+v", r)
	}
	// IP-адрес не резолвится, UDP не проверяется по TCP
	hy := Server{Type: "hysteria2", Host: "1.2.3.4", Port: 8443}
	p = okProbe()
	p.TCP = func(string) error { t.Fatal("tcp must not run for hysteria2"); return nil }
	if r := runLinkDiag(hy, true, p); r.Level != "ok" {
		t.Fatalf("hy2: %+v", r)
	}
}
