package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// A local, password-protected proxy inside sing-box. Its user name picks the exit:
// "route" follows the rules like a browser, "proxy" forces the active server, "direct" skips the server,
// "s<N>" forces the saved server number N. The app uses it to check services and measure speed.

func probePort(st Settings) int { return st.APIPort + 1 }

func probeInbound(st Settings, exits []exitSpec) m {
	users := []m{
		{"username": probeUserRoute, "password": st.APISecret},
		{"username": probeUserProxy, "password": st.APISecret},
		{"username": probeUserDirect, "password": st.APISecret},
	}
	for _, e := range exits {
		users = append(users, m{"username": e.User, "password": st.APISecret})
	}
	return m{"type": "mixed", "tag": "probe-in", "listen": "127.0.0.1", "listen_port": probePort(st), "users": users}
}

func probeClient(st Settings, user string, timeout time.Duration) *http.Client {
	u := &url.URL{Scheme: "http", User: url.UserPassword(user, st.APISecret), Host: fmt.Sprintf("127.0.0.1:%d", probePort(st))}
	tr := &http.Transport{
		Proxy:               http.ProxyURL(u),
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// ---- service checks

const (
	lvOK      = "ok"
	lvBad     = "bad"
	lvUnknown = "unknown"
)

type svcProbe struct {
	ID, Name, URL string
	Judge         func(status int, finalURL, body string) (level, note string)
}

func containsAny(s string, subs ...string) bool {
	s = strings.ToLower(s)
	for _, x := range subs {
		if strings.Contains(s, strings.ToLower(x)) {
			return true
		}
	}
	return false
}

var svcProbes = []svcProbe{
	{"gemini", "Gemini (сайт)", "https://gemini.google.com/app", func(st int, fu, b string) (string, string) {
		if containsAny(b, "not supported in your country", "isn't currently supported", "isn’t currently supported", "не поддерживается в вашей стране") {
			return lvBad, "Google пишет, что Gemini не поддерживается в стране этого адреса"
		}
		if st == 200 {
			return lvOK, "страница открывается (для чата нужен вход в аккаунт)"
		}
		return lvUnknown, fmt.Sprintf("ответ %d", st)
	}},
	{"geminiapi", "Gemini (API)", "https://generativelanguage.googleapis.com/v1beta/models", func(st int, fu, b string) (string, string) {
		if containsAny(b, "location is not supported") {
			return lvBad, "API не поддерживается в стране этого адреса"
		}
		if st == 400 || st == 401 || st == 403 || st == 200 {
			return lvOK, "доступ есть (нужен ключ API)"
		}
		return lvUnknown, fmt.Sprintf("ответ %d", st)
	}},
	{"openai", "ChatGPT / OpenAI (API)", "https://api.openai.com/v1/models", func(st int, fu, b string) (string, string) {
		if containsAny(b, "unsupported_country_region_territory") {
			return lvBad, "OpenAI не обслуживает страну этого адреса"
		}
		if st == 401 || st == 200 {
			return lvOK, "доступ есть (нужен ключ API)"
		}
		return lvUnknown, fmt.Sprintf("ответ %d", st)
	}},
	{"claude", "Claude (сайт)", "https://claude.ai/", func(st int, fu, b string) (string, string) {
		if containsAny(fu, "unavailable-in-region", "app-unavailable") || containsAny(b, "app-unavailable-in-region") {
			return lvBad, "Claude недоступен в стране этого адреса"
		}
		if st == 200 {
			return lvOK, "страница открывается"
		}
		if st == 403 {
			return lvUnknown, "403: проверка Cloudflare, в браузере может открыться"
		}
		return lvUnknown, fmt.Sprintf("ответ %d", st)
	}},
	{"anthropic", "Claude (API)", "https://api.anthropic.com/v1/models", func(st int, fu, b string) (string, string) {
		if st == 401 {
			return lvOK, "доступ есть (нужен ключ API)"
		}
		if st == 403 {
			return lvBad, "API не обслуживает страну этого адреса"
		}
		return lvUnknown, fmt.Sprintf("ответ %d", st)
	}},
	{"netflix", "Netflix", "https://www.netflix.com/title/81280792", func(st int, fu, b string) (string, string) {
		switch {
		case st == 200:
			return lvOK, "каталог открывается"
		case st == 404:
			return lvBad, "Netflix не показывает каталог для этого адреса"
		}
		return lvUnknown, fmt.Sprintf("ответ %d", st)
	}},
	{"spotify", "Spotify", "https://open.spotify.com/", func(st int, fu, b string) (string, string) {
		if st == 200 {
			return lvOK, "открывается"
		}
		return lvUnknown, fmt.Sprintf("ответ %d", st)
	}},
	{"youtube", "YouTube", "https://www.youtube.com/", func(st int, fu, b string) (string, string) {
		if st == 200 {
			return lvOK, "открывается"
		}
		return lvUnknown, fmt.Sprintf("ответ %d", st)
	}},
	{"telegram", "Telegram (сайт)", "https://web.telegram.org/", openJudge},
	{"discord", "Discord", "https://discord.com/api/v9/gateway", openJudge},
	{"steam", "Steam (магазин)", "https://store.steampowered.com/", openJudge},
	{"steamcom", "Steam (сообщество)", "https://steamcommunity.com/", openJudge},
	{"tiktok", "TikTok", "https://www.tiktok.com/", openJudge},
	{"instagram", "Instagram", "https://www.instagram.com/", openJudge},
	{"twitch", "Twitch", "https://www.twitch.tv/", openJudge},
	{"github", "GitHub", "https://github.com/", openJudge},
}

// openJudge: for ordinary sites it is enough that the page opens; a refusal usually means the site dislikes this address.
func openJudge(st int, fu, b string) (string, string) {
	switch {
	case st >= 200 && st < 300:
		return lvOK, "открывается"
	case st == 403 || st == 451:
		return lvBad, fmt.Sprintf("сайт отказал этому адресу (%d). Возможно, он не пускает адрес сервера", st)
	case st == 429:
		return lvUnknown, "слишком много запросов (429), проверь позже"
	}
	return lvUnknown, fmt.Sprintf("ответ %d", st)
}

type SvcResult struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Level string `json:"level"`
	Note  string `json:"note"`
	Ms    int    `json:"ms"`
}

func runProbe(ctx context.Context, cl *http.Client, p svcProbe) SvcResult {
	r := SvcResult{ID: p.ID, Name: p.Name}
	req, err := http.NewRequestWithContext(ctx, "GET", p.URL, nil)
	if err != nil {
		r.Level, r.Note = lvUnknown, err.Error()
		return r
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	t0 := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		r.Level, r.Note = lvBad, "не удалось соединиться: "+shortErr(err)
		return r
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 200000))
	r.Ms = int(time.Since(t0).Milliseconds())
	r.Level, r.Note = p.Judge(resp.StatusCode, resp.Request.URL.String(), string(b))
	return r
}

// exitInfo asks Cloudflare which address and country it sees.
func exitInfo(ctx context.Context, cl *http.Client) (ip, loc string) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.cloudflare.com/cdn-cgi/trace", nil)
	resp, err := cl.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "ip="); ok {
			ip = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(l, "loc="); ok {
			loc = strings.TrimSpace(v)
		}
	}
	return
}

// POST /api/svccheck {server: -1 (active) | index of a saved server}
func (a *App) handleSvcCheck(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Server int `json:"server"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if !a.core.Running() {
		fail(w, 400, "сначала включи обход")
		return
	}
	st := a.settings()
	user := probeUserProxy
	label := serverKey(st.Server)
	if in.Server >= 0 {
		servers := allServers(st)
		if in.Server >= len(servers) || len(servers) < 2 {
			fail(w, 400, "нет такого сервера")
			return
		}
		user = probeUserFor(in.Server)
		label = serverKey(servers[in.Server])
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	cl := probeClient(st, user, 15*time.Second)
	res := make([]SvcResult, len(svcProbes))
	var wg sync.WaitGroup
	for i, p := range svcProbes {
		wg.Add(1)
		go func(i int, p svcProbe) {
			defer wg.Done()
			res[i] = runProbe(ctx, cl, p)
		}(i, p)
	}
	ip, loc := exitInfo(ctx, cl)
	wg.Wait()
	writeJSON(w, 200, map[string]any{"ok": true, "server": label, "exitIp": ip, "exitCountry": loc, "results": res})
}

// ---- speed test

type SpeedResult struct {
	Label  string  `json:"label"`
	Mbit   float64 `json:"mbit"`
	TTFBms int     `json:"ttfbMs"`
	Error  string  `json:"error,omitempty"`
}

const speedBytes = 10_000_000

func measureSpeed(ctx context.Context, cl *http.Client, label string) SpeedResult {
	res := SpeedResult{Label: label}
	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", speedBytes), nil)
	t0 := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		res.Error = shortErr(err)
		return res
	}
	defer resp.Body.Close()
	res.TTFBms = int(time.Since(t0).Milliseconds())
	t1 := time.Now()
	n, err := io.Copy(io.Discard, resp.Body)
	d := time.Since(t1).Seconds()
	if n < 100_000 {
		if err == nil {
			err = errors.New("ответ слишком короткий")
		}
		res.Error = shortErr(err)
		return res
	}
	if d < 0.05 {
		d = 0.05
	}
	res.Mbit = float64(n) * 8 / d / 1e6
	if err != nil {
		res.Error = "оборвалось, измерено по полученному"
	}
	return res
}

func (a *App) handleSpeed(w http.ResponseWriter, r *http.Request) {
	if !a.core.Running() {
		fail(w, 400, "сначала включи обход")
		return
	}
	st := a.settings()
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	direct := measureSpeed(ctx, probeClient(st, probeUserDirect, 20*time.Second), "Напрямую")
	via := measureSpeed(ctx, probeClient(st, probeUserProxy, 20*time.Second), "Через сервер")
	writeJSON(w, 200, map[string]any{"ok": true, "results": []SpeedResult{direct, via}})
}
