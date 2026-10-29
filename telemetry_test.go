package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestScrubMsg(t *testing.T) {
	cases := map[string]string{
		"dial tcp 203.0.113.10:443: i/o timeout":        "dial tcp <ip>: i/o timeout",
		"lookup hoop.un1v249.ru: no such host":          "lookup <host>: no such host",
		`open C:\Users\Ivan\AppData\x\core.out: denied`: "open <path>: denied",
		"get https://t.me/x?a=1 failed":                 "get <url> failed",
		"Нет связи с сервером уже 5 мин.":               "Нет связи с сервером уже N мин.",
		"key 3f2b1c9d-aaaa-bbbb-cccc-1234567890ab bad":  "key <id> bad",
		"token AbCdEfGhIjKlMnOpQrStUvWxYz0123 x":        "token <key> x",
		"Сервер не отвечает, переключаюсь на «Шадоу». Перезапускаю": "Сервер не отвечает, переключаюсь на «<имя>». Перезапускаю",
		"mail me@example.com":               "mail <mail>",
		"open /home/ivan/.config/x: denied": "open <path>: denied",
	}
	for in, want := range cases {
		if got := scrubMsg(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	if n := len([]rune(scrubMsg(strings.Repeat("слово ", 100)))); n > 162 {
		t.Errorf("не обрезано: %d", n)
	}
}

func TestTeleQueueDedup(t *testing.T) {
	var q teleQueue
	now := time.Now()
	q.add("bad", "Нет связи 5 мин", now)
	q.add("bad", "Нет связи 7 мин", now)
	q.add("warn", "", now) // пустое не пишем
	l := q.snapshot()
	if len(l) != 1 || l[0].N != 2 {
		t.Fatalf("%+v", l)
	}
	if l[0].M != "Нет связи N мин" {
		t.Fatal(l[0].M)
	}
}

func TestStackFuncs(t *testing.T) {
	st := "goroutine 7 [running]:\nruntime/debug.Stack()\n\t/usr/go/debug/stack.go:26 +0x5e\nmain.(*App).recordPanic(0xc0, {0x1, 0x2})\n\t/home/u/x.go:1\nmain.(*App).watchdog(0xc0)\n\t/home/u/y.go:2\n"
	got := stackFuncs([]byte(st), 4)
	if got != "(*App).watchdog" || strings.Contains(got, "/") {
		t.Fatal(got)
	}
}

func TestTeleFlushAndOff(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	a := &App{dataDir: t.TempDir(), core: &Core{}, quit: make(chan struct{}), st: Settings{Telemetry: "on", InstallID: "abc123", ReportURL: srv.URL + "/report"}}
	a.tele("bad", "Нет связи 3 мин")
	if err := a.flushTele(); err != nil {
		t.Fatal(err)
	}
	if got["id"] != "abc123" || got["v"] == nil || len(got["events"].([]any)) != 1 {
		t.Fatalf("%v", got)
	}
	// выключено: ничего не копится и не уходит
	a.st.Telemetry = "off"
	a.tele("bad", "x")
	if len(a.teleq.snapshot()) != 0 {
		t.Fatal("копится при off")
	}
	// сервер недоступен: события возвращаются
	srv.Close()
	a.st.Telemetry = "on"
	a.tele("bad", "y")
	if err := a.flushTele(); err == nil || len(a.teleq.snapshot()) != 1 {
		t.Fatalf("err=%v q=%v", err, a.teleq.snapshot())
	}
}

func TestPanicRecorded(t *testing.T) {
	a := &App{dataDir: t.TempDir(), core: &Core{}, quit: make(chan struct{}), st: Settings{Telemetry: "on", InstallID: "z"}}
	done := make(chan struct{})
	a.guardGo("тест", func() { defer close(done); panic("boom 42") })
	<-done
	time.Sleep(50 * time.Millisecond)
	l := a.teleq.snapshot()
	if len(l) != 1 || l[0].K != "panic" || !strings.Contains(l[0].M, "boom N") {
		t.Fatalf("%+v", l)
	}
	a.teleq.take()
	a.teleCrashFile()
	if len(a.teleq.snapshot()) != 1 {
		t.Fatal("crash.txt не прочитан")
	}
}

func TestScrubCoversWhatTheSettingsPromise(t *testing.T) {
	for in, leak := range map[string]string{
		"dial tcp: lookup claude.ai: no such host":           "claude.ai",
		"server shadow-01.example.space unreachable":         "example.space",
		"open process Discord.exe: access denied":            "Discord",
		"dial 2a00:1450:4010:c05::71 port 443":               "2a00",
		"inbound: connection to chat.mistral.ai:443 refused": "mistral",
	} {
		if out := scrubMsg(in); strings.Contains(out, leak) {
			t.Fatalf("%q leaks %q: %q", in, leak, out)
		}
	}
	if out := scrubMsg("sing-box.exe exited"); !strings.Contains(out, "sing-box.exe") {
		t.Fatalf("our own component name must stay: %q", out)
	}
}
