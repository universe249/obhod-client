package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 1. a failed DPAPI decrypt must not destroy the secrets: the old file is kept and the tunnel says why it cannot start
func TestUndecryptableSecretsAreKept(t *testing.T) {
	oldP, oldU := protectFn, unprotectFn
	secretsUnreadable.Store(false)
	t.Cleanup(func() { protectFn, unprotectFn = oldP, oldU; secretsUnreadable.Store(false) })
	protectFn = func(b []byte) ([]byte, error) { return append([]byte("X"), b...), nil }
	dir := t.TempDir()
	s := defaultSettings()
	s.Server = Server{Type: "vless", Host: "h", Port: 443, UUID: "uuid-secret", Name: "n"}
	s.SubURL = "https://sub.example/secret"
	if err := saveSettings(dir, s); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(filepath.Join(dir, "settings.json"))
	if !strings.Contains(string(orig), "dpapi:") {
		t.Skip("secrets are not sealed on this platform")
	}
	unprotectFn = func([]byte) ([]byte, error) { return nil, errors.New("другой пользователь") }
	st := loadSettings(dir)
	if st.Server.UUID != "" {
		t.Fatal("an unreadable secret must read as empty")
	}
	if !secretsLostFor(st.Server) {
		t.Fatal("the active server should be reported as having lost its credentials")
	}
	_ = saveSettings(dir, st) // main() does this right after loading
	kept, err := os.ReadFile(filepath.Join(dir, unreadableBackup))
	if err != nil || string(kept) != string(orig) {
		t.Fatalf("the original file was not kept: %v", err)
	}
	// the right user can still read the kept copy
	unprotectFn = func(b []byte) ([]byte, error) { return b[1:], nil }
	_ = os.WriteFile(filepath.Join(dir, "settings.json"), kept, 0o600)
	if back := loadSettings(dir); back.Server.UUID != "uuid-secret" || back.SubURL != "https://sub.example/secret" {
		t.Fatalf("the kept copy does not restore: %+v", back.Server)
	}
	// the tunnel refuses to start with a clear message instead of a cryptic config error
	secretsUnreadable.Store(true)
	c := &Core{dataDir: t.TempDir()}
	err = c.Start(Settings{Server: Server{Type: "vless", Host: "h", Port: 443}})
	if err == nil || !strings.Contains(err.Error(), "другим пользователем Windows") {
		t.Fatalf("expected the clear error, got %v", err)
	}
	// a server that never had secrets is not blamed
	if secretsLostFor(Server{Host: "h", Password: "p"}) {
		t.Fatal("false alarm")
	}
}

// 2. the restart limiter is shared by the watchdog and the network watcher: no data race, exactly 3 per window
func TestAllowRestartIsThreadSafeAndLimited(t *testing.T) {
	a := &App{}
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if a.allowRestart() {
					ok.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 3 {
		t.Fatalf("allowed %d restarts, want 3", ok.Load())
	}
	// old entries expire
	a.restartMu.Lock()
	a.restarts = []time.Time{time.Now().Add(-11 * time.Minute), time.Now().Add(-12 * time.Minute), time.Now().Add(-13 * time.Minute)}
	a.restartMu.Unlock()
	if !a.allowRestart() {
		t.Fatal("restarts older than 10 minutes must not count")
	}
}

// 4. after the pace limit the watchdog does not give up for good: the tunnel stays wanted
func TestWatchdogKeepsWantingAfterLimit(t *testing.T) {
	a := &App{}
	a.setWant(true)
	a.restartMu.Lock()
	a.restarts = []time.Time{time.Now(), time.Now(), time.Now()}
	a.restartMu.Unlock()
	a.autoRestart("test") // limited: returns before touching the core
	if !a.wanted() {
		t.Fatal("the watchdog must not switch the tunnel off for good")
	}
	// the notice is rate limited (autoRestart already used the first one)
	if a.shouldTellGiveUp() {
		t.Fatal("the notice must be shown at most once per 30 minutes")
	}
}

// 3. a process that a newer start has replaced must not wipe the newer one or report a crash
func TestReapIgnoresReplacedProcess(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	var crashes atomic.Int32
	c := &Core{dataDir: t.TempDir(), onCrash: func(string) { crashes.Add(1) }}
	old := exec.Command(sleep, "30")
	if err := old.Start(); err != nil {
		t.Fatal(err)
	}
	newer := exec.Command(sleep, "30")
	if err := newer.Start(); err != nil {
		t.Fatal(err)
	}
	defer newer.Process.Kill()
	c.mu.Lock()
	c.cmd = newer // the newer start has already taken over
	c.mu.Unlock()
	done := make(chan struct{})
	go c.reap(old, nil, done)
	_ = old.Process.Kill() // the slow old process finally dies
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reap did not finish")
	}
	if !c.Running() {
		t.Fatal("the old process wiped the state of the newer one")
	}
	if crashes.Load() != 0 {
		t.Fatal("a replaced process must not be reported as a crash")
	}
	// and the normal case still works: the current process ends -> not running, crash reported
	cur := exec.Command(sleep, "30")
	if err := cur.Start(); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.cmd = cur
	c.mu.Unlock()
	done2 := make(chan struct{})
	go c.reap(cur, nil, done2)
	_ = cur.Process.Kill()
	<-done2
	if c.Running() {
		t.Fatal("the current process ended but the core is still marked running")
	}
	if crashes.Load() != 1 {
		t.Fatalf("a real crash must be reported once, got %d", crashes.Load())
	}
}

// 3b. Start and Stop never run at the same time
func TestCoreLifecycleIsSerialized(t *testing.T) {
	c := &Core{dataDir: t.TempDir()}
	c.lifeMu.Lock()
	finished := make(chan struct{})
	go func() {
		c.Stop()
		close(finished)
	}()
	select {
	case <-finished:
		t.Fatal("Stop ran while a start/stop was in progress")
	case <-time.After(150 * time.Millisecond):
	}
	c.lifeMu.Unlock()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop never ran")
	}
}

// 5. servers that disappeared from the subscription are marked, never deleted, and failover skips them
func srv(name string, port int) Server {
	return Server{Name: name, Type: "vless", Host: name + ".example", Port: port, UUID: "u-" + name, Network: "tcp"}
}

func TestGoneServersAreMarkedNotDeleted(t *testing.T) {
	st := &Settings{}
	syncProfiles(st, []Server{srv("a", 1), srv("b", 2), srv("c", 3)})
	if len(st.Profiles) != 3 || !st.Profiles[0].FromSub {
		t.Fatalf("setup: %+v", st.Profiles)
	}
	manual := srv("m", 9)
	syncProfilesOpt(st, []Server{manual}, false) // pasted by hand
	if st.Profiles[3].FromSub {
		t.Fatal("a hand-pasted link must not be treated as part of the subscription")
	}
	// the subscription no longer lists b
	syncProfiles(st, []Server{srv("a", 1), srv("c", 3)})
	if len(st.Profiles) != 4 {
		t.Fatalf("nothing may be deleted, have %d", len(st.Profiles))
	}
	if st.Profiles[0].Gone || !st.Profiles[1].Gone || st.Profiles[2].Gone || st.Profiles[3].Gone {
		t.Fatalf("wrong marks: %+v", st.Profiles)
	}
	// a broken (empty) answer never marks anything
	st2 := &Settings{}
	syncProfiles(st2, []Server{srv("a", 1), srv("b", 2)})
	syncProfiles(st2, nil)
	if st2.Profiles[0].Gone || st2.Profiles[1].Gone {
		t.Fatal("an empty subscription must not mark servers")
	}
	// it comes back
	syncProfiles(st, []Server{srv("a", 1), srv("b", 2), srv("c", 3)})
	if st.Profiles[1].Gone {
		t.Fatal("a returned server must be cleared")
	}
	// a legacy entry (no flags) matching the subscription becomes tracked
	st3 := &Settings{Profiles: []Server{srv("x", 5)}}
	syncProfiles(st3, []Server{srv("x", 5), srv("y", 6)})
	if !st3.Profiles[0].FromSub {
		t.Fatal("an old entry that is in the subscription should become tracked")
	}
}

func TestFailoverSkipsGoneServers(t *testing.T) {
	a := &App{dataDir: t.TempDir()}
	a.st.Failover, a.st.SlowSwitch = true, true
	a.st.Profiles = []Server{srv("a", 1), srv("b", 2), srv("c", 3)}
	a.st.Profiles[1].Gone = true
	a.st.Server = a.st.Profiles[0]
	name, ok := a.failoverNext()
	if !ok || name != "c" {
		t.Fatalf("failoverNext = %q %v, want c (b is gone)", name, ok)
	}
	a.st.Server = a.st.Profiles[0]
	a.st.Profiles[2].Type = "hysteria2" // c differs in protocol, b (vless) is gone
	name, _ = a.failoverSlow()
	if name != "c" {
		t.Fatalf("failoverSlow = %q, want c", name)
	}
	// when everything else is gone the old behaviour (just the next one) is kept
	b := &App{dataDir: t.TempDir()}
	b.st.Failover = true
	b.st.Profiles = []Server{srv("a", 1), srv("b", 2)}
	b.st.Profiles[1].Gone = true
	b.st.Server = b.st.Profiles[0]
	if name, ok := b.failoverNext(); !ok || name != "b" {
		t.Fatalf("with only gone servers left we still switch: %q %v", name, ok)
	}
}

func TestNextAliveWraps(t *testing.T) {
	l := []Server{srv("a", 1), srv("b", 2), srv("c", 3)}
	l[2].Gone = true
	if got := nextAlive(l, 1); got != 0 {
		t.Fatalf("nextAlive(1) = %d, want 0", got)
	}
	if got := nextAlive(l, -1); got != 0 {
		t.Fatalf("nextAlive(-1) = %d, want 0", got)
	}
}

func TestSrvStatsSkipGone(t *testing.T) {
	s := newSrvStats(t.TempDir())
	list := []Server{srv("a", 1), srv("b", 2), srv("c", 3)}
	list[1].Gone = true
	for _, id := range []Server{list[1], list[2]} {
		for i := 0; i < 10; i++ {
			s.record("net", 1, srvID(id), true, 50)
		}
	}
	for _, i := range s.order(list, list[0], "net", 1) {
		if list[i].Gone {
			t.Fatal("order returned a gone server")
		}
	}
}

func TestRotateLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.log")
	_ = os.WriteFile(p, []byte("small"), 0o600)
	rotateLog(p, 10)
	if _, err := os.Stat(p + ".1"); err == nil {
		t.Fatal("a small log must stay")
	}
	_ = os.WriteFile(p, []byte(strings.Repeat("x", 50)), 0o600)
	rotateLog(p, 10)
	if _, err := os.Stat(p); err == nil {
		t.Fatal("a big log must move away")
	}
	if b, _ := os.ReadFile(p + ".1"); len(b) != 50 {
		t.Fatal("the big log must be kept as .1")
	}
}

func TestReindexScheduleAfterPresetDelete(t *testing.T) {
	rules := []SchedRule{
		{Time: "08:00", Action: "preset", Preset: "u:0"},
		{Time: "09:00", Action: "preset", Preset: "u:1"},
		{Time: "10:00", Action: "preset", Preset: "u:2"},
		{Time: "11:00", Action: "preset", Preset: "b:global"},
		{Time: "12:00", Action: "on"},
	}
	got := reindexSchedule(rules, 1)
	if len(got) != 4 || got[0].Preset != "u:0" || got[1].Preset != "u:1" || got[1].Time != "10:00" || got[2].Preset != "b:global" {
		t.Fatalf("%+v", got)
	}
}

func TestHy2MultiPortInAddress(t *testing.T) {
	s, err := parseLink("hysteria2://pw@h.com:443,20000-30000/?sni=h.com#hop")
	if err != nil || s.Port != 443 || s.HopPorts != "443,20000-30000" || s.Host != "h.com" || s.Name != "hop" {
		t.Fatalf("%v %+v", err, s)
	}
	s, err = parseLink("hy2://pw@[2001:db8::1]:20000-30000?sni=h.com")
	if err != nil || s.Port != 20000 || s.HopPorts != "20000-30000" || s.Host != "2001:db8::1" {
		t.Fatalf("%v %+v", err, s)
	}
	s, err = parseLink("hysteria2://pw@h.com:443?mport=1000-2000")
	if err != nil || s.Port != 443 || s.HopPorts != "1000-2000" {
		t.Fatalf("%v %+v", err, s)
	}
	if _, err := parseLink("vless://u@h.com:443?security=tls&type=tcp&headerType=http"); err == nil {
		t.Fatal("tcp with http header must be refused, not silently broken")
	}
	if _, err := parseLink("vless://u@h.com:443?security=tls&type=tcp&headerType=none"); err != nil {
		t.Fatal(err)
	}
}

func TestRenamedInboundIsUpdatedNotDuplicated(t *testing.T) {
	st := &Settings{}
	a := srv("a", 1)
	syncProfiles(st, []Server{a, srv("b", 2)})
	st.Server = st.Profiles[0]
	r := a
	r.Name = "a-renamed"
	syncProfiles(st, []Server{r, srv("b", 2)})
	if len(st.Profiles) != 2 || st.Profiles[0].Name != "a-renamed" || st.Profiles[0].Gone || st.Server.Name != "a-renamed" {
		t.Fatalf("%+v / %+v", st.Profiles, st.Server)
	}
}

func TestAllServersSkipsGone(t *testing.T) {
	st := Settings{Server: srv("a", 1)}
	st.Profiles = []Server{srv("a", 1), srv("b", 2), srv("c", 3)}
	st.Profiles[1].Gone = true
	got := allServers(st)
	if len(got) != 2 || got[1].Name != "c" {
		t.Fatalf("%+v", got)
	}
	st.Server = st.Profiles[1] // the user deliberately chose a gone one: it still works
	if got := allServers(st); got[0].Name != "b" {
		t.Fatalf("%+v", got)
	}
}

func TestNetSnapshotIgnoresVirtualAdapters(t *testing.T) {
	wifi := ifaceInfo{Name: "Wi-Fi", Up: true, Addrs: []string{"192.168.1.5"}}
	wsl := ifaceInfo{Name: "vEthernet (WSL)", Up: true, Addrs: []string{"172.28.80.1"}}
	a, ka := netSnapshot([]ifaceInfo{wifi})
	b, kb := netSnapshot([]ifaceInfo{wifi, wsl})
	if a != b || ka != kb {
		t.Fatal("starting WSL must not look like a new network")
	}
	// a Hyper-V external switch: the only connection is a vEthernet adapter, it must still count
	ext := ifaceInfo{Name: "vEthernet (External)", Up: true, Addrs: []string{"192.168.1.5"}}
	if s, _ := netSnapshot([]ifaceInfo{ext}); s == "" {
		t.Fatal("the only real connection was ignored")
	}
}

// the settings card "Что нового" stayed empty: the list was rendered before "const WHATS_NEW" was declared
func TestWhatsNewRenderedAfterDeclaration(t *testing.T) {
	b, err := os.ReadFile("ui.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	decl := strings.Index(s, "const WHATS_NEW=[")
	use := strings.Index(s, `getElementById("wnList").innerHTML=whatsNewHtml()`)
	if decl < 0 || use < 0 || use < decl {
		t.Fatalf("decl at %d, render at %d", decl, use)
	}
}
