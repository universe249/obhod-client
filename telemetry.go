package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// Анонимные отчёты об ошибках. Работают только если пользователь сам включил их в настройках.
// Отправляется: версия программы, система, случайный номер установки, вид события и обезличенный текст.
// Не отправляется: адреса сайтов, IP, пути, ключи, ссылки, имена программ и содержимое трафика.

type TeleEvent struct {
	K string `json:"k"` // start | panic | crash | warn | bad
	M string `json:"m"` // обезличенный текст
	N int    `json:"n"` // сколько раз
	T int64  `json:"t"`
}

type teleQueue struct {
	mu     sync.Mutex
	list   []TeleEvent
	last   string // последний отправленный пакет, чтобы показать его пользователю
	lastAt int64
}

const teleKeep = 60

var (
	reURL   = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://\S+`)
	reMail  = regexp.MustCompile(`[\w.+-]+@[\w-]+(\.[\w-]+)+`)
	reIP    = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b|\[[0-9a-fA-F:]{3,}\](:\d+)?`)
	reWPath = regexp.MustCompile(`(?i)\b[a-z]:\\[^\s"'<>|]*[^\s"'<>|:,;.)]`)
	reUPath = regexp.MustCompile(`(^|[\s"'(=])/[\w.-]+(/[\w.@-]+)+`)
	reHost  = regexp.MustCompile(`(?i)\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(com|net|org|ru|su|рф|io|me|info|xyz|app|dev|cloud|pro|top|site|online|tv|gg|to|cc|co|eu|de|nl|fi|uk|us|ua|by|kz|ai|so|sh|im|ly|fm|gl|is|it|fr|es|pl|cz|jp|cn|kr|in|br|tr|il|ch|at|se|no|dk|ca|au|nz|biz|space|tech|fun|one|ws|link|club|live|store|shop|host|website|works|page|art|chat|network|digital|world|today|news|media|video|game|games|studio|email|run|social|zone|lol|cat|vpn|win|icu|life|team|tools|ink|ooo|xn--p1ai)\b`)
	reApp   = regexp.MustCompile(`(?i)\b[\w.-]+\.(exe|dll)\b`)
	reIP6   = regexp.MustCompile(`(?i)\b[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}\b`)
	reLong  = regexp.MustCompile(`[A-Za-z0-9+/=_-]{20,}`)
	reHexID = regexp.MustCompile(`(?i)\b[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\b`)
	reName  = regexp.MustCompile(`«[^»]*»|"[^"]{1,60}"`)
	reNum   = regexp.MustCompile(`\d+`)
	reSpace = regexp.MustCompile(`\s+`)
)

// scrubMsg убирает из текста всё, что может указать на человека или сервер, и приводит числа к виду «N»,
// чтобы одинаковые ошибки складывались в одну строку.
func scrubMsg(s string) string {
	s = reName.ReplaceAllString(s, "«<имя>»")
	s = reURL.ReplaceAllString(s, "<url>")
	s = reMail.ReplaceAllString(s, "<mail>")
	s = reHexID.ReplaceAllString(s, "<id>")
	s = reIP.ReplaceAllString(s, "<ip>")
	s = reIP6.ReplaceAllString(s, "<ip>")
	s = reApp.ReplaceAllStringFunc(s, func(m string) string {
		switch strings.ToLower(m) {
		case "sing-box.exe", "xray.exe":
			return m // our own components: the name is needed to understand the error
		}
		return "<app>"
	})
	s = reWPath.ReplaceAllString(s, "<path>")
	s = reUPath.ReplaceAllString(s, "${1}<path>")
	s = reHost.ReplaceAllString(s, "<host>")
	s = reLong.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "<") {
			return m
		}
		return "<key>"
	})
	s = reNum.ReplaceAllString(s, "N")
	s = reSpace.ReplaceAllString(strings.TrimSpace(s), " ")
	if r := []rune(s); len(r) > 160 {
		s = string(r[:160]) + "…"
	}
	return s
}

func (q *teleQueue) add(kind, msg string, now time.Time) {
	msg = scrubMsg(msg)
	if kind != "start" && msg == "" {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := range q.list {
		if q.list[i].K == kind && q.list[i].M == msg {
			q.list[i].N++
			q.list[i].T = now.Unix()
			return
		}
	}
	q.list = append(q.list, TeleEvent{K: kind, M: msg, N: 1, T: now.Unix()})
	if len(q.list) > teleKeep {
		q.list = q.list[len(q.list)-teleKeep:]
	}
}

func (q *teleQueue) take() []TeleEvent {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.list
	q.list = nil
	return out
}

func (q *teleQueue) putBack(ev []TeleEvent) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.list = append(ev, q.list...)
	if len(q.list) > teleKeep {
		q.list = q.list[len(q.list)-teleKeep:]
	}
}

func (q *teleQueue) snapshot() []TeleEvent {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]TeleEvent(nil), q.list...)
}

// teleOn: отчёты включены.
func (a *App) teleOn() bool { return a.settings().Telemetry == "on" }

// tele записывает событие, если пользователь согласился.
func (a *App) tele(kind, msg string) {
	if !a.teleOn() {
		return
	}
	a.teleq.add(kind, msg, time.Now())
}

func teleURL(st Settings) string {
	base := st.ReportURL
	if base == "" {
		base = defaultReportURL
	}
	if i := strings.LastIndex(base, "/"); i > 8 {
		base = base[:i]
	}
	return base + "/telemetry"
}

func teleOS() string { return runtime.GOOS + "/" + runtime.GOARCH }

// flushTele отправляет накопленное. При неудаче события возвращаются в очередь.
func (a *App) flushTele() error {
	st := a.settings()
	if st.Telemetry != "on" || st.InstallID == "" {
		a.teleq.take()
		return nil
	}
	ev := a.teleq.take()
	if len(ev) == 0 {
		return nil
	}
	running, _, _, _, _ := a.core.Info()
	body, _ := json.Marshal(map[string]any{"id": st.InstallID, "v": appVersion, "os": teleOS(), "vpn": running, "events": ev})
	resp, err := (&http.Client{Timeout: 12 * time.Second}).Post(teleURL(st), "application/json", bytes.NewReader(body))
	if err != nil {
		a.teleq.putBack(ev)
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != 200 {
		if resp.StatusCode >= 500 {
			a.teleq.putBack(ev)
		}
		return fmt.Errorf("сервер ответил %d", resp.StatusCode)
	}
	a.teleq.mu.Lock()
	a.teleq.last, a.teleq.lastAt = string(body), time.Now().Unix()
	a.teleq.mu.Unlock()
	return nil
}

func (a *App) teleLoop() {
	if a.teleOn() {
		a.tele("start", "")
		a.teleCrashFile()
	}
	lastBeat := time.Now()
	timer := time.NewTimer(30 * time.Second)
	for {
		select {
		case <-a.quit:
			return
		case <-timer.C:
		}
		if a.teleOn() && time.Since(lastBeat) > 23*time.Hour {
			a.tele("start", "") // раз в сутки: «установка жива», иначе в статистике видны только перезапуски и ошибки
			lastBeat = time.Now()
		}
		if err := a.flushTele(); err != nil {
			log.Printf("telemetry: %v", err)
		}
		timer.Reset(10 * time.Minute)
	}
}

// stackFuncs оставляет в стеке только имена функций (без путей и аргументов).
func stackFuncs(stack []byte, max int) string {
	var fn []string
	for _, ln := range strings.Split(string(stack), "\n") {
		if ln == "" || strings.HasPrefix(ln, "\t") || strings.HasPrefix(ln, "goroutine ") {
			continue
		}
		if strings.HasPrefix(ln, "runtime/debug.") || strings.HasPrefix(ln, "panic(") || strings.HasPrefix(ln, "runtime.") ||
			strings.Contains(ln, "recordPanic") || strings.Contains(ln, "guardGo") {
			continue
		}
		if i := strings.LastIndex(ln, "("); i > 0 && !strings.HasPrefix(ln[i:], "(*") {
			ln = ln[:i]
		}
		ln = strings.TrimPrefix(strings.TrimPrefix(ln, "main."), "singui.")
		fn = append(fn, ln)
		if len(fn) >= max {
			break
		}
	}
	return strings.Join(fn, " < ")
}

func panicText(r any, stack []byte) string {
	return fmt.Sprintf("%v @ %s", r, stackFuncs(stack, 4))
}

func crashPath(dataDir string) string { return filepath.Join(dataDir, "crash.txt") }

// guardGo запускает фоновую задачу так, чтобы паника не убила программу молча: она пишется в журнал и в crash.txt.
func (a *App) guardGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				a.recordPanic(name, r, debug.Stack())
			}
		}()
		fn()
	}()
}

func (a *App) recordPanic(name string, r any, stack []byte) {
	txt := panicText(r, stack)
	log.Printf("panic in %s: %v\n%s", name, r, stack)
	f, err := os.OpenFile(crashPath(a.dataDir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err == nil {
		fmt.Fprintf(f, "%s\t%s\n", name, strings.ReplaceAll(txt, "\n", " "))
		f.Close()
	}
	a.events.add("bad", "Внутренняя ошибка в «"+name+"», программа продолжает работать", time.Now())
	a.tele("panic", name+": "+txt)
}

// teleCrashFile отправляет то, что записалось в crash.txt до перезапуска.
func (a *App) teleCrashFile() {
	b, err := os.ReadFile(crashPath(a.dataDir))
	if err != nil {
		return
	}
	for i, ln := range strings.Split(string(b), "\n") {
		if i >= 10 {
			break
		}
		if p := strings.SplitN(ln, "\t", 2); len(p) == 2 {
			a.tele("panic", p[0]+": "+p[1])
		}
	}
	_ = os.Remove(crashPath(a.dataDir))
}

func (a *App) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var in struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || (in.Mode != "on" && in.Mode != "off") {
			fail(w, 400, "неверный запрос")
			return
		}
		a.mu.Lock()
		a.st.Telemetry = in.Mode
		if in.Mode == "on" && a.st.InstallID == "" {
			a.st.InstallID = randHex(8)
		}
		a.rev.Add(1)
		st := a.st
		a.mu.Unlock()
		if err := saveSettings(a.dataDir, st); err != nil {
			fail(w, 500, err.Error())
			return
		}
		if in.Mode == "off" {
			a.teleq.take()
		} else {
			a.teleq.add("start", "", time.Now())
		}
	}
	st := a.settings()
	a.teleq.mu.Lock()
	last, lastAt := a.teleq.last, a.teleq.lastAt
	a.teleq.mu.Unlock()
	writeJSON(w, 200, map[string]any{"mode": st.Telemetry, "installId": st.InstallID, "version": appVersion, "os": teleOS(),
		"pending": a.teleq.snapshot(), "last": last, "lastAt": lastAt})
}

// lastLine возвращает последнюю непустую строку: в конце журнала ядра обычно сама причина.
func lastLine(s string) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(ls) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(ls[i]); t != "" {
			return t
		}
	}
	return ""
}
