package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed ui.html
var uiHTML []byte

//go:embed mini.html
var miniHTML []byte

// appName is the display name (window title, tray, autostart task); override with -ldflags "-X main.appName=Name".
//
//go:embed assets/logo.png
var logoPNG []byte

//go:embed assets/ico64.png
var faviconPNG []byte

//go:embed assets/logo_off.png
var logoOffPNG []byte

//go:embed assets/logo_bad.png
var logoBadPNG []byte

//go:embed assets/vasya/*.webp
var vasyaFS embed.FS

var appName = "Обход для чайников"

// appVersion is set at build time: -X main.appVersion=3.4
var appVersion = "dev"

type App struct {
	chatUnread atomic.Int32 // новых ответов поддержки, пока окно их не показало
	uiLight    atomic.Bool  // в главном окне светлая тема (для мини-панели)
	links      linkLog      // журнал связи по путям за сутки
	dataDir    string
	token      string
	core       *Core
	mu         sync.Mutex
	pending    string // ссылка из obhod://, ждёт подтверждения в окне
	showWin    func()
	st         Settings
	quit       chan struct{}
	quitOnce   sync.Once
	health     Health
	wantOn     bool
	restartMu  sync.Mutex // guards restarts and lastGiveUp: the watchdog and the network watcher both restart the tunnel
	restarts   []time.Time
	lastGiveUp time.Time
	upd        Updater
	stats      *Stats
	ads        *adCounter
	suspects   *suspectTracker
	radar      radar
	hist       *History
	hints      hintCache
	rev        atomic.Int64 // bumped when the program changes settings on its own (failover, tray, restore)
	conf       conflictCache
	tune       tuneState
	events     eventLog
	trace      traceState
	hogs       hogTracker
	teleq      teleQueue
	hk         hotkeyHost
	net        netState
	srv        *srvStats
	dnsBusy    atomic.Bool
}

func (a *App) doQuit() {
	a.quitOnce.Do(func() {
		a.setWant(false)
		trayRemove()
		a.core.Stop()
		close(a.quit)
	})
}

func (a *App) settings() Settings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.st
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func (a *App) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if !(strings.HasPrefix(host, "127.0.0.1:") || strings.HasPrefix(host, "localhost:")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		ck, err := r.Cookie("singui")
		if err != nil || ck.Value != a.token {
			fail(w, http.StatusUnauthorized, "нет доступа")
			return
		}
		if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			fail(w, http.StatusBadRequest, "ожидается JSON")
			return
		}
		next(w, r)
	}
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !(strings.HasPrefix(host, "127.0.0.1:") || strings.HasPrefix(host, "localhost:")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if t := r.URL.Query().Get("t"); t != "" {
		if t == a.token {
			http.SetCookie(w, &http.Cookie{Name: "singui", Value: a.token, Path: "/", HttpOnly: true,
				SameSite: http.SameSiteStrictMode, MaxAge: 86400 * 365})
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}
	if ck, err := r.Cookie("singui"); err != nil || ck.Value != a.token {
		http.Error(w, "Открой приложение через значок "+appName, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(bytes.ReplaceAll(bytes.ReplaceAll(uiHTML, []byte("SingUI"), []byte(appName)), []byte("{{VERSION}}"), []byte("v"+appVersion)))
}

func (a *App) serverSummary(s Server) string {
	if s.Host == "" {
		return ""
	}
	return fmt.Sprintf("%s · %s:%d", s.Type, s.Host, s.Port)
}

// pendingLink отдаёт ссылку из obhod:// ровно один раз и сразу забывает её: так её получит только одно окно/вкладка
// и диалог не повторится, даже если опрашивают сразу несколько окон.
func (a *App) pendingLink() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := a.pending
	a.pending = ""
	return v
}

// POST /api/show — открыть (показать) окно программы; зовёт повторный запуск.
func (a *App) handleShow(w http.ResponseWriter, r *http.Request) {
	if a.showWin != nil {
		go a.showWin()
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/deeplink {link} — ссылка obhod://…, пришедшая из другого запуска. POST /api/pendinglink — сбросить.
func (a *App) handleDeepLink(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Link  string `json:"link"`
		Clear bool   `json:"clear"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if in.Clear {
		a.mu.Lock()
		a.pending = ""
		a.mu.Unlock()
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	v, ok := parseDeepLink(in.Link)
	if !ok {
		fail(w, 400, "неверная ссылка")
		return
	}
	a.mu.Lock()
	a.pending = v
	a.mu.Unlock()
	a.rev.Add(1)
	if a.showWin != nil {
		go a.showWin()
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleState(w http.ResponseWriter, r *http.Request) {
	st := a.settings()
	running, pid, up, lastErr, hash := a.core.Info()
	bin := a.core.binPath(st)
	res := map[string]any{
		"running":     running,
		"pid":         pid,
		"uptimeSec":   int(up.Seconds()),
		"pendingLink": a.pendingLink(),
		"error":       lastErr,
		"admin":       isAdmin(),
		"version":     appVersion,
		"rev":         a.rev.Load(),
		"update":      a.upd.snapshot(),
		"coreFound":   bin != "",
		"corePath":    bin,
		"hasServer":   st.Server.Host != "",
		"serverName":  st.Server.Name,
		"server":      a.serverSummary(st.Server),
		"autostart":   autostartEnabled(),
		"needsXray":   needsXray(st.Server),
		"warnings":    a.core.Warnings(),
		"conflicts":   a.conf.get(),
		"rollback":    hasRollback(),
		"gameMode":    st.GameMode,
		"uiLight":     a.uiLight.Load(),
		"adBlock":     st.AdBlock,
		"globalLeft":  tempGlobalLeft(st, time.Now()),
		"gameApps":    len(st.GameApps),
		"hints":       a.currentHints(),
		"events":      a.events.recent(8),
	}
	if running {
		res["path"] = currentPath(st)
	}
	res["chat"] = st.AppToken != ""
	res["chatUnread"] = a.chatUnread.Load()
	hs, hms := a.health.Get()
	res["health"] = hs
	res["pingMs"] = hms
	if xb := a.core.xrayBin(st); xb != "" {
		res["xrayFound"] = true
		res["xrayPath"] = xb
	}
	if bin != "" {
		res["coreVersion"] = a.core.Version(bin)
	}
	if running {
		if h := fullHash(st, a.dataDir, a.core.Skip()); h != "" {
			res["dirty"] = h != hash
		}
		var cn struct {
			Up   int64             `json:"uploadTotal"`
			Down int64             `json:"downloadTotal"`
			C    []json.RawMessage `json:"connections"` // нужно только число: без разбора каждого соединения вдвое быстрее
		}
		if err := clashGet(st, "/connections", &cn); err == nil {
			res["ready"] = true
			res["upTotal"] = cn.Up
			res["downTotal"] = cn.Down
			res["conns"] = len(cn.C)
		} else {
			res["ready"] = false
		}
	}
	writeJSON(w, 200, res)
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		st := a.settings()
		st.APISecret, st.AppToken = "", ""
		writeJSON(w, 200, map[string]any{"settings": st, "catalog": catalog})
		return
	}
	var in Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	a.mu.Lock()
	in.APISecret, in.AppToken = a.st.APISecret, a.st.AppToken // окно эти поля не видит и не меняет
	in.GlobalUntil = a.st.GlobalUntil                         // меняется только через /api/tempglobal
	if in.UIPort == 0 {
		in.UIPort = a.st.UIPort
	}
	if in.APIPort == 0 {
		in.APIPort = a.st.APIPort
	}
	if in.Services == nil {
		in.Services = map[string]bool{}
	}
	a.st = in
	a.mu.Unlock()
	if err := saveSettings(a.dataDir, in); err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleImport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	srv, err := parseLink(in.Link)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.mu.Lock()
	a.st.Server = srv
	st := a.st
	a.mu.Unlock()
	if err := saveSettings(a.dataDir, st); err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "server": srv})
}

func (a *App) handleCore(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.URL.Path, "/api/core/")
	st := a.settings()
	switch action {
	case "start":
		a.setWant(true)
		// a double click or a start from the tray at the same moment: already running is not a failure
		if err := a.core.Start(st); err != nil && !errors.Is(err, errAlreadyRunning) {
			a.setWant(false)
			fail(w, 400, err.Error())
			return
		}
	case "stop":
		a.setWant(false)
		a.core.Stop()
	case "restart":
		a.setWant(true)
		a.core.Stop()
		if err := startedOK(a.core.Start(st)); err != nil {
			a.setWant(false)
			fail(w, 400, err.Error())
			return
		}
	case "download-xray":
		tag, err := a.core.DownloadXray()
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "version": tag})
		return
	case "killall":
		a.setWant(false)
		a.core.Stop()
		writeJSON(w, 200, map[string]any{"ok": true, "output": killAllCore(a.dataDir)})
		return
	default:
		fail(w, 404, "неизвестное действие")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

type connView struct {
	Host    string `json:"host"`
	Dest    string `json:"dest"`
	Process string `json:"process"`
	Via     string `json:"via"`
	Rule    string `json:"rule"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
	Start   string `json:"start"`
	Net     string `json:"net"`
}

func (a *App) handleConnections(w http.ResponseWriter, r *http.Request) {
	st := a.settings()
	var cn struct {
		Connections []struct {
			Metadata struct {
				Network string `json:"network"`
				DestIP  string `json:"destinationIP"`
				Port    string `json:"destinationPort"`
				Host    string `json:"host"`
				Process string `json:"processPath"`
			} `json:"metadata"`
			Up      int64    `json:"upload"`
			Down    int64    `json:"download"`
			Start   string   `json:"start"`
			Chains  []string `json:"chains"`
			Rule    string   `json:"rule"`
			Payload string   `json:"rulePayload"`
		} `json:"connections"`
	}
	if err := clashGet(st, "/connections", &cn); err != nil {
		writeJSON(w, 200, map[string]any{"connections": []connView{}})
		return
	}
	out := make([]connView, 0, len(cn.Connections))
	for _, c := range cn.Connections {
		via := "direct"
		if len(c.Chains) > 0 {
			via = c.Chains[0]
		}
		proc := c.Metadata.Process
		if i := strings.LastIndexAny(proc, `\/`); i >= 0 {
			proc = proc[i+1:]
		}
		dest := c.Metadata.DestIP
		if c.Metadata.Port != "" {
			dest += ":" + c.Metadata.Port
		}
		rule := c.Rule
		if c.Payload != "" {
			rule += " " + c.Payload
		}
		out = append(out, connView{Host: c.Metadata.Host, Dest: dest, Process: proc, Via: via,
			Rule: rule, Up: c.Up, Down: c.Down, Start: c.Start, Net: c.Metadata.Network})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start > out[j].Start })
	if len(out) > 200 {
		out = out[:200]
	}
	writeJSON(w, 200, map[string]any{"connections": out})
}

func (a *App) handlePing(w http.ResponseWriter, r *http.Request) {
	st := a.settings()
	var res struct {
		Delay int `json:"delay"`
	}
	err := clashGet(st, "/proxies/proxy/delay?url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=5000", &res)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "нет ответа через сервер"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "ms": res.Delay})
}

func (a *App) handleLog(w http.ResponseWriter, r *http.Request) {
	text := stripANSI(tailFile(filepath.Join(a.dataDir, "box.log"), 60000))
	lines := strings.Split(text, "\n")
	if len(lines) > 400 {
		lines = lines[len(lines)-400:]
	}
	if r.URL.Query().Get("errors") == "1" {
		var f []string
		for _, l := range lines {
			u := strings.ToUpper(l)
			if strings.Contains(u, "ERROR") || strings.Contains(u, "FATAL") || strings.Contains(u, "WARN") {
				f = append(f, l)
			}
		}
		lines = f
	}
	extra := strings.TrimSpace(stripANSI(tailFile(filepath.Join(a.dataDir, "core.out"), 4000)))
	if xl := strings.TrimSpace(stripANSI(tailFile(filepath.Join(a.dataDir, "xray.log"), 4000) + tailFile(filepath.Join(a.dataDir, "xray.out"), 2000))); xl != "" {
		extra += "\n\n— Xray —\n" + xl
	}
	writeJSON(w, 200, map[string]any{"lines": lines, "coreOut": extra})
}

func (a *App) handleConfig(w http.ResponseWriter, r *http.Request) {
	b, err := configBytes(a.settings(), a.dataDir, a.core.Skip())
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	var cfg map[string]any
	_ = json.Unmarshal(b, &cfg)
	if exp, ok := cfg["experimental"].(map[string]any); ok {
		if c, ok := exp["clash_api"].(map[string]any); ok {
			c["secret"] = "***"
		}
	}
	if xb, err := xrayConfigBytes(a.settings(), a.dataDir); err == nil {
		var xc map[string]any
		if json.Unmarshal(xb, &xc) == nil {
			cfg["_xray_config"] = xc
		}
	}
	writeJSON(w, 200, cfg)
}

func (a *App) handleRuleSets(w http.ResponseWriter, r *http.Request) {
	st := a.settings()
	if r.Method == http.MethodPost {
		_, errs := ensureRuleSets(st, a.dataDir, true)
		writeJSON(w, 200, map[string]any{"sets": ruleSetStatus(st, a.dataDir), "errors": errs})
		return
	}
	writeJSON(w, 200, map[string]any{"sets": ruleSetStatus(st, a.dataDir)})
}

func (a *App) handleAutostart(w http.ResponseWriter, r *http.Request) {
	var in struct {
		On bool `json:"on"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if err := setAutostart(in.On); err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleQuit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true})
	go func() {
		time.Sleep(200 * time.Millisecond)
		a.doQuit()
	}()
}

// sendToRunning отправляет запрос уже запущенному экземпляру программы.
func sendToRunning(port int, token, path string, body map[string]any) bool {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d%s", port, path), bytes.NewReader(b))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "singui", Value: token})
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func pingExisting(port int, token string) bool {
	c := &http.Client{Timeout: 800 * time.Millisecond}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/api/hello", port), nil)
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func main() {
	// встроенное ядро: второй экземпляр программы, без окна (см. corerun.go)
	if len(os.Args) > 1 && os.Args[1] == coreFlag {
		os.Exit(coreMain(os.Args[2:], os.Stdout, os.Stderr))
	}
	background := flag.Bool("background", false, "не открывать окно")
	resume := flag.Bool("resume", false, "включить туннель (после обновления, если он был включён)")
	flag.Parse()

	exe, _ := os.Executable()
	dataDir := filepath.Join(filepath.Dir(exe), "data")
	if v := os.Getenv("SINGUI_DATA"); v != "" {
		dataDir = v
	}
	if isCLI(flag.Args()) {
		out, errw := attachConsole()
		os.Exit(runCLI(flag.Args(), dataDir, out, errw))
	}
	_ = os.MkdirAll(dataDir, 0o755)

	rotateLog(filepath.Join(dataDir, "singui.log"), 5<<20)
	rotateLog(filepath.Join(dataDir, "fatal.log"), 5<<20)
	if f, err := os.OpenFile(filepath.Join(dataDir, "singui.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		log.SetOutput(f)
	}
	// фатальные ошибки Go (без паники, которую можно перехватить) пишутся в этот файл, иначе их не видно
	if f, err := os.OpenFile(filepath.Join(dataDir, "fatal.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		_ = debug.SetCrashOutput(f, debug.CrashOptions{})
	}

	hostIPs.load(dataDir)
	hwidFile = filepath.Join(dataDir, "device.id")
	st := loadSettings(dataDir)
	_ = saveSettings(dataDir, st)

	tokenPath := filepath.Join(dataDir, "token")
	tb, err := os.ReadFile(tokenPath)
	token := strings.TrimSpace(string(tb))
	if err != nil || len(token) < 16 {
		token = randHex(16)
		_ = os.WriteFile(tokenPath, []byte(token), 0o600)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/?t=%s", st.UIPort, token)

	// Already running? Just show the window.
	deep := ""
	for _, a := range flag.Args() {
		if v, ok := parseDeepLink(a); ok {
			deep = a
			_ = v
		}
	}
	if pingExisting(st.UIPort, token) {
		if deep != "" && sendToRunning(st.UIPort, token, "/api/deeplink", map[string]any{"link": deep}) {
			return
		}
		if !*background && !sendToRunning(st.UIPort, token, "/api/show", map[string]any{}) {
			openAppWindow(url, dataDir)
		}
		return
	}

	if !isAdmin() && os.Getenv("SINGUI_NOADMIN") == "" {
		if relaunchAsAdmin() == nil {
			return
		}
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", st.UIPort))
	if err != nil {
		log.Printf("listen: %v", err)
		os.Exit(1)
	}

	initJob()
	go registerProtocol(exe)
	app := &App{dataDir: dataDir, token: token, core: &Core{dataDir: dataDir}, st: st, quit: make(chan struct{}), stats: newStats(dataDir), ads: newAdCounter(dataDir), suspects: newSuspectTracker(), hist: newHistory(dataDir), srv: newSrvStats(dataDir)}

	app.showWin = func() { openAppWindow(url, dataDir) }
	if deep != "" {
		if v, ok := parseDeepLink(deep); ok {
			app.pending = v
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleIndex)
	mux.HandleFunc("/mini", app.handleMini)
	mux.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "max-age=86400")
		_, _ = w.Write(logoPNG)
	})
	mux.HandleFunc("/vasya/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/vasya/")
		if name == "" || strings.ContainsAny(name, "/\\") {
			http.NotFound(w, r)
			return
		}
		b, err := vasyaFS.ReadFile("assets/vasya/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/webp")
		w.Header().Set("Cache-Control", "max-age=86400")
		_, _ = w.Write(b)
	})
	for path, data := range map[string][]byte{"/logo_off.png": logoOffPNG, "/logo_bad.png": logoBadPNG} {
		data := data
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "max-age=86400")
			_, _ = w.Write(data)
		})
	}
	mux.HandleFunc("/favicon.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "max-age=86400")
		_, _ = w.Write(faviconPNG)
	})
	mux.HandleFunc("/api/hello", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"app": "singui"}) })
	mux.HandleFunc("/api/state", app.guard(app.handleState))
	mux.HandleFunc("/api/settings", app.guard(app.handleSettings))
	mux.HandleFunc("/api/import", app.guard(app.handleImport))
	mux.HandleFunc("/api/update", app.guard(app.handleUpdate))
	mux.HandleFunc("/api/profiles", app.guard(app.handleProfiles))
	mux.HandleFunc("/api/export", app.guard(app.handleExport))
	mux.HandleFunc("/api/report", app.guard(app.handleReport))
	mux.HandleFunc("/api/show", app.guard(app.handleShow))
	mux.HandleFunc("/api/deeplink", app.guard(app.handleDeepLink))
	mux.HandleFunc("/api/sendreport", app.guard(app.handleSendReport))
	mux.HandleFunc("/api/explain", app.guard(app.handleExplain))
	mux.HandleFunc("/api/stats", app.guard(app.handleStats))
	mux.HandleFunc("/api/svccheck", app.guard(app.handleSvcCheck))
	mux.HandleFunc("/api/tune", app.guard(app.handleTune))
	mux.HandleFunc("/api/speedtest", app.guard(app.handleSpeed))
	mux.HandleFunc("/api/hints", app.guard(app.handleHints))
	mux.HandleFunc("/api/presets", app.guard(app.handlePresets))
	mux.HandleFunc("/api/lists", app.guard(app.handleLists))
	mux.HandleFunc("/api/hogs", app.guard(app.handleHogs))
	mux.HandleFunc("/api/qr", app.guard(app.handleQR))
	mux.HandleFunc("/api/hotkeys", app.guard(app.handleHotkeys))
	mux.HandleFunc("/api/telemetry", app.guard(app.handleTelemetry))
	mux.HandleFunc("/api/trace", app.guard(app.handleTrace))
	mux.HandleFunc("/api/dnscheck", app.guard(app.handleDNSCheck))
	mux.HandleFunc("/api/history", app.guard(app.handleHistory))
	mux.HandleFunc("/api/srvstats", app.guard(app.handleSrvStats))
	mux.HandleFunc("/api/leak", app.guard(app.handleLeak))
	mux.HandleFunc("/api/backups", app.guard(app.handleBackups))
	mux.HandleFunc("/api/game", app.guard(app.handleGame))
	mux.HandleFunc("/api/wintheme", app.guard(app.handleWinTheme))
	mux.HandleFunc("/api/core/", app.guard(app.handleCore))
	mux.HandleFunc("/api/connections", app.guard(app.handleConnections))
	mux.HandleFunc("/api/ping", app.guard(app.handlePing))
	mux.HandleFunc("/api/login", app.guard(app.handleLogin))
	mux.HandleFunc("/api/route", app.guard(app.handleRoute))
	mux.HandleFunc("/api/chat", app.guard(app.handleChat))
	mux.HandleFunc("/api/linklog", app.guard(app.handleLinkLog))
	mux.HandleFunc("/api/log", app.guard(app.handleLog))
	mux.HandleFunc("/api/config", app.guard(app.handleConfig))
	mux.HandleFunc("/api/autostart", app.guard(app.handleAutostart))
	mux.HandleFunc("/api/rulesets", app.guard(app.handleRuleSets))
	mux.HandleFunc("/api/diagnose", app.guard(app.handleDiagnose))
	mux.HandleFunc("/api/linkdiag", app.guard(app.handleLinkDiag))
	mux.HandleFunc("/api/diagnose/add", app.guard(app.handleDiagnoseAdd))
	mux.HandleFunc("/api/processes", app.guard(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"processes": listProcesses()})
	}))
	mux.HandleFunc("/api/tempglobal", app.guard(app.handleTempGlobal))
	mux.HandleFunc("/api/adblock", app.guard(app.handleAdBlock))
	mux.HandleFunc("/api/minilog", app.guard(app.handleMiniLog))
	mux.HandleFunc("/api/adstats", app.guard(app.handleAdStats))
	mux.HandleFunc("/api/suggest", app.guard(app.handleSuggest))
	mux.HandleFunc("/api/quit", app.guard(app.handleQuit))

	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("serve: %v", err)
		}
	}()

	app.startAdDNS() // до запуска ядра: в конфиг попадает порт счётчика рекламы
	if (st.StartCore || *resume) && st.Server.Host != "" {
		app.setWant(true)
		if err := app.core.Start(st); err != nil {
			app.setWant(false)
			log.Printf("autostart core: %v", err)
		}
	}
	startTray(trayHandlers{
		Open: func() { openAppWindow(url, dataDir) },
		Panel: func() {
			if app.settings().TrayOpensWindow {
				openAppWindow(url, dataDir)
				return
			}
			log.Printf("мини-панель: щелчок по значку")
			if !toggleMiniPanel(strings.Replace(url, "/?t=", "/mini?t=", 1), dataDir, func() { openAppWindow(url, dataDir) }) {
				app.event("warn", "Мини-панель не открылась, открыто обычное окно (подробности в журнале программы)")
				openAppWindow(url, dataDir)
			}
		},
		Toggle: func() { app.toggleTunnel(false) },
		Quit:   app.doQuit,
		IsOn:   app.core.Running,
		Profiles: func() ([]string, int) {
			st := app.settings()
			names := make([]string, len(st.Profiles))
			for i, p := range st.Profiles {
				names[i] = p.Name
				if names[i] == "" {
					names[i] = p.Host
				}
			}
			return names, profileIndex(st)
		},
		Pick: func(i int) {
			name, err := app.useProfile(i)
			if err != nil {
				app.notify(appName, "Не удалось переключить сервер: "+err.Error())
				return
			}
			app.notify(appName, "Сервер: «"+name+"»")
		},
		Game: func() (bool, bool) {
			st := app.settings()
			return len(st.GameApps) > 0, st.GameMode
		},
		ToggleGame: app.toggleGame,
		TempGlobal: func() (bool, bool) {
			st := app.settings()
			return st.Mode != "global" && st.Server.Host != "", tempGlobalLeft(st, time.Now()) > 0
		},
		ToggleTempGlobal: app.toggleTempGlobal,
	})
	app.core.onCrash = func(msg string) { app.tele("crash", "sing-box: "+lastLine(msg)) }
	app.guardGo("watchdog", app.watchdog)
	app.guardGo("updateLoop", app.updateLoop)
	app.guardGo("collectStats", app.collectStats)
	app.guardGo("historyFlushLoop", app.historyFlushLoop)
	app.guardGo("backupLoop", app.backupLoop)
	app.guardGo("subscriptionLoop", app.subscriptionLoop)
	app.guardGo("listsLoop", app.listsLoop)
	app.guardGo("autoGameLoop", app.autoGameLoop)
	app.guardGo("teleLoop", app.teleLoop)
	app.guardGo("netWatchLoop", app.netWatchLoop)
	app.guardGo("pathWatchLoop", app.pathWatchLoop)
	app.guardGo("tempGlobalLoop", app.tempGlobalLoop)
	app.guardGo("chatLoop", app.chatLoop)
	app.guardGo("linkLogLoop", app.linkLogLoop)
	app.guardGo("schedLoop", app.schedLoop)
	app.applyHotkeys()
	app.guardGo("srvStatsLoop", app.srvStatsLoop)
	go func() {
		last := -1
		var meter speedMeter
		for tick := 0; ; tick++ {
			s := app.trayStateNow()
			if s != last {
				trayUpdate(s)
				last = s
			}
			if tick%3 == 0 {
				traySetInfo(app.trayInfoNow(&meter))
			}
			select {
			case <-app.quit:
				return
			case <-time.After(time.Second):
			}
		}
	}()
	if !*background {
		openAppWindow(url, dataDir)
	}
	<-app.quit
	_ = srv.Close()
}
