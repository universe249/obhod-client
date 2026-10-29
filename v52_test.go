package main

import (
	"testing"
	"time"
)

func TestEventLogKeepsNewestFirstAndCollapsesRepeats(t *testing.T) {
	var e eventLog
	now := time.Unix(1000, 0)
	e.add("info", "a", now)
	e.add("info", "a", now.Add(10*time.Second)) // repeat: only refreshes
	e.add("bad", "b", now.Add(20*time.Second))
	got := e.recent(5)
	if len(got) != 2 || got[0].Text != "b" || got[1].Text != "a" || got[1].T != 1010 {
		t.Fatalf("unexpected events: %+v", got)
	}
	for i := 0; i < 100; i++ {
		e.add("info", itoa(i), now.Add(time.Duration(100+i)*time.Minute))
	}
	if n := len(e.recent(1000)); n != eventsKeep {
		t.Fatalf("kept %d, want %d", n, eventsKeep)
	}
}

func TestEventKind(t *testing.T) {
	cases := map[string]string{
		"Связь с сервером восстановлена.":                 "ok",
		"Нет связи с сервером.":                           "bad",
		"Сервер не отвечает, переключаюсь на «Германия».": "bad",
		"Связь нестабильная, переключаюсь на «Германия».": "warn",
		"Подписка заканчивается через 2 дн.":              "warn",
		"Доступна новая версия 5.2.":                      "info",
	}
	for text, want := range cases {
		if got := eventKind(text); got != want {
			t.Errorf("%q: got %s want %s", text, got, want)
		}
	}
}

func TestSubAlerts(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	exp := func(d time.Duration) int64 { return now.Add(d).Unix() }
	if got := subAlerts(nil, now); got != nil {
		t.Fatal("nil meta must give no alerts")
	}
	if got := subAlerts(&SubMeta{Expire: exp(10 * 24 * time.Hour), Total: 100, Used: 50}, now); len(got) != 0 {
		t.Fatalf("healthy subscription: %+v", got)
	}
	got := subAlerts(&SubMeta{Expire: exp(48 * time.Hour)}, now)
	if len(got) != 1 || got[0].Text != "Подписка заканчивается через 2 дн." {
		t.Fatalf("3-day alert: %+v", got)
	}
	got = subAlerts(&SubMeta{Expire: exp(5 * time.Hour), Total: 100, Used: 95}, now)
	if len(got) != 2 || got[0].Key[:4] != "exp1" || got[1].Key[:3] != "t90" {
		t.Fatalf("expiry+traffic: %+v", got)
	}
	got = subAlerts(&SubMeta{Expire: exp(-time.Hour), Total: 100, Used: 100}, now)
	if len(got) != 2 || got[0].Key[:4] != "exp0" || got[1].Key[:4] != "full" {
		t.Fatalf("expired: %+v", got)
	}
	// renewal changes the key
	a := subAlerts(&SubMeta{Expire: exp(5 * time.Hour)}, now)[0].Key
	b := subAlerts(&SubMeta{Expire: exp(6 * time.Hour)}, now)[0].Key
	if a == b {
		t.Fatal("key must change when expiry changes")
	}
}

func TestCheckSubAlertsNotifiesOnce(t *testing.T) {
	dir := t.TempDir()
	a := &App{dataDir: dir, quit: make(chan struct{})}
	a.st = defaultSettings()
	a.st.Notify = false
	a.st.SubMeta = &SubMeta{Expire: time.Now().Add(20 * time.Hour).Unix(), Total: 100, Used: 95}
	a.checkSubAlerts()
	if n := len(a.events.recent(10)); n != 2 {
		t.Fatalf("first run: %d events", n)
	}
	a.checkSubAlerts()
	if n := len(a.events.recent(10)); n != 2 {
		t.Fatalf("second run must not repeat: %d events", n)
	}
	a.st.SubMeta.Used = 10 // traffic reset, alert goes away and may come back later
	a.checkSubAlerts()
	if len(a.st.SubAlerted) != 1 {
		t.Fatalf("alerted: %v", a.st.SubAlerted)
	}
}

func TestPresets(t *testing.T) {
	dir := t.TempDir()
	a := &App{dataDir: dir, quit: make(chan struct{}), core: &Core{}}
	a.st = defaultSettings()
	a.st.Services = map[string]bool{"youtube": true}
	a.st.GameApps = []string{"dota2.exe"}

	views := presetViews(a.st)
	if len(views) != 3 || !views[0].Active || views[1].Active {
		t.Fatalf("default views: %+v", views)
	}
	if err := a.applyPresetID("b:global"); err != nil {
		t.Fatal(err)
	}
	if a.st.Mode != "global" || !presetViews(a.st)[1].Active {
		t.Fatalf("global not applied: %+v", a.st.Mode)
	}
	if err := a.applyPresetID("b:games"); err != nil || !a.st.GameMode || a.st.Mode != "smart" {
		t.Fatalf("games: %v %+v", err, a.st.Mode)
	}
	a.st.GameApps = nil
	if err := a.applyPresetID("b:smart"); err != nil || a.st.GameMode {
		t.Fatal("smart must turn game mode off")
	}
	if err := a.applyPresetID("b:games"); err == nil {
		t.Fatal("games preset without game apps must fail")
	}

	// user preset: snapshot, change settings, apply back
	a.st.Services = map[string]bool{"youtube": true, "discord": true}
	a.st.ProxyApps = []string{"Discord.exe"}
	a.st.Presets = append(a.st.Presets, snapshotPreset("Работа", a.st))
	a.st.Services = map[string]bool{}
	a.st.ProxyApps = nil
	a.st.Mode = "global"
	if presetViews(a.st)[3].Active {
		t.Fatal("must not be active after changes")
	}
	if err := a.applyPresetID("u:0"); err != nil {
		t.Fatal(err)
	}
	if !a.st.Services["discord"] || len(a.st.ProxyApps) != 1 || a.st.Mode != "smart" || !presetViews(a.st)[3].Active {
		t.Fatalf("preset not restored: %+v", a.st)
	}
	if err := a.applyPresetID("u:9"); err == nil {
		t.Fatal("unknown preset must fail")
	}
}
