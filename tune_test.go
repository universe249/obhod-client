package main

import (
	"strings"
	"testing"
)

func TestTuneCandidatesMatchConfig(t *testing.T) {
	st := multiSettings()
	cfg := cfgOf(t, st)
	tags := outTags(cfg)
	// every candidate must be reachable through the running config
	users := map[string]bool{}
	for _, in := range cfg["inbounds"].([]any) {
		if mm := in.(map[string]any); mm["tag"] == "probe-in" {
			for _, u := range mm["users"].([]any) {
				users[u.(map[string]any)["username"].(string)] = true
			}
		}
	}
	routed := map[string]string{}
	for _, r := range cfg["route"].(map[string]any)["rules"].([]any) {
		mm := r.(map[string]any)
		if au, ok := mm["auth_user"].([]any); ok {
			routed[au[0].(string)], _ = mm["outbound"].(string)
		}
	}
	cs := tuneCandidates(st)
	if len(cs) == 0 {
		t.Fatal("no candidates")
	}
	var frag, mux int
	for _, c := range cs {
		if !users[c.User] {
			t.Fatalf("user %s not in probe inbound", c.User)
		}
		if c.User != probeUserProxy {
			if _, ok := tags[routed[c.User]]; !ok {
				t.Fatalf("user %s routes to missing outbound %q", c.User, routed[c.User])
			}
		}
		switch c.Kind {
		case kindFrag:
			frag++
		case kindMux:
			mux++
		}
	}
	// two vless servers get both ways; hysteria2 gets neither
	if frag != 2 || mux != 2 {
		t.Fatalf("frag=%d mux=%d: %+v", frag, mux, cs)
	}
	for _, c := range cs {
		if c.Name == "NL" && c.Kind != kindBase {
			t.Fatal("hysteria2 must not get ways")
		}
	}
}

func TestWaysChangeOutbound(t *testing.T) {
	st := multiSettings()
	for _, o := range cfgOf(t, st)["outbounds"].([]any) {
		mm := o.(map[string]any)
		switch mm["tag"] {
		case "srv-0-f":
			if tl, _ := mm["tls"].(map[string]any); tl["fragment"] != true {
				t.Fatal("frag way must fragment")
			}
		case "srv-0-m":
			mx, _ := mm["multiplex"].(map[string]any)
			if mx["enabled"] != true {
				t.Fatal("mux way must multiplex")
			}
		case "proxy":
			if _, has := mm["multiplex"]; has {
				t.Fatal("active server must not multiplex by default")
			}
		}
	}
	st.Server.Mux = true
	st.Profiles[0].Mux = true
	var got bool
	for _, o := range cfgOf(t, st)["outbounds"].([]any) {
		if mm := o.(map[string]any); mm["tag"] == "proxy" {
			_, got = mm["multiplex"]
		}
	}
	if !got {
		t.Fatal("Server.Mux ignored")
	}
	// XTLS vision cannot be multiplexed
	v := Server{Type: "vless", Host: "x.com", Port: 443, UUID: "u", Flow: "xtls-rprx-vision", Security: "tls"}
	if muxable(v) {
		t.Fatal("vision flow must not mux")
	}
}

func TestPickWinner(t *testing.T) {
	mk := func(active bool, ok, ms int, mbit float64) tuneCand {
		c := tuneCand{Active: active, Ok: ok, Ms: ms, Mbit: mbit}
		c.Score = scoreOf(c)
		return c
	}
	// the active one is dead, another works
	cs := []tuneCand{mk(true, 0, 0, 0), mk(false, 3, 400, 12)}
	if w := pickWinner(cs); w != 1 {
		t.Fatalf("dead active: %d", w)
	}
	// slight improvement is not worth switching
	cs = []tuneCand{mk(true, 3, 400, 10), mk(false, 3, 400, 11)}
	if w := pickWinner(cs); w != -1 {
		t.Fatalf("flip-flop: %d", w)
	}
	// clear improvement is
	cs = []tuneCand{mk(true, 3, 900, 1), mk(false, 3, 300, 10)}
	if w := pickWinner(cs); w != 1 {
		t.Fatalf("clear: %d", w)
	}
	// nothing works
	cs = []tuneCand{mk(true, 0, 0, 0), mk(false, 1, 5000, 0)}
	if w := pickWinner(cs); w != -1 {
		t.Fatalf("all dead: %d", w)
	}
	// stalled stream (reachable but no speed) loses against a measured one
	cs = []tuneCand{mk(true, 3, 300, 0), mk(false, 3, 500, 5)}
	if w := pickWinner(cs); w != 1 {
		t.Fatalf("stalled: %d", w)
	}
}

func TestApplyCand(t *testing.T) {
	a := &App{dataDir: t.TempDir(), st: multiSettings()}
	// fragmentation way of the second server: switches to it and turns fragmentation on
	name := a.applyCand(tuneCand{Server: 1, Kind: kindFrag, Way: "с фрагментацией TLS"})
	if !strings.Contains(name, "US") {
		t.Fatalf("name %q", name)
	}
	st := a.settings()
	if st.Server.Host != "2.2.2.2" || st.Server.Frag != "on" {
		t.Fatalf("%+v", st.Server)
	}
	if st.Profiles[1].Frag != "on" {
		t.Fatal("saved copy not updated")
	}
	// mux way on the same server
	a.applyCand(tuneCand{Server: 0, Kind: kindMux, Way: "с мультиплексированием"})
	if !a.settings().Server.Mux {
		t.Fatal("mux not applied")
	}
	if a.applyCand(tuneCand{Server: 99}) != "" {
		t.Fatal("bad index accepted")
	}
}

func TestMedian(t *testing.T) {
	if r := median([]int{5, 1, 3}); r != 3 {
		t.Fatal(r)
	}
	if median(nil) != 0 {
		t.Fatal("median of nothing")
	}
}

func TestBestIndexIgnoresMargin(t *testing.T) {
	mk := func(active bool, ok, ms int, mbit float64) tuneCand {
		c := tuneCand{Active: active, Ok: ok, Ms: ms, Mbit: mbit}
		c.Score = scoreOf(c)
		return c
	}
	// numbers from a real run: the best one is only ~24% ahead, so "winner" stays -1 but best is known
	cs := []tuneCand{mk(true, 3, 253, 50.5), mk(false, 3, 393, 59.0), mk(false, 3, 196, 59.7), mk(false, 3, 156, 57.4)}
	if pickWinner(cs) != -1 {
		t.Fatal("margin must hold")
	}
	if b := bestIndex(cs); b != 2 {
		t.Fatalf("best %d", b)
	}
	if bestIndex([]tuneCand{mk(true, 0, 0, 0)}) != -1 {
		t.Fatal("nothing works")
	}
}
