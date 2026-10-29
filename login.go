package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Вход через Telegram: бот выдаёт одноразовый код, человек подтверждает его в боте, приложение получает ссылку-подписку.
// Только HTTPS: код на время входа — ключ к подписке, по открытому HTTP его можно подсмотреть.
const loginBase = "https://hoop.un1v249.ru:8444"

var loginClient = &http.Client{Timeout: 12 * time.Second}

type loginReply struct {
	Code   string `json:"code"`
	URL    string `json:"url"`
	Status string `json:"status"`
	Sub    string `json:"sub"`
	Name   string `json:"name"`
	Token  string `json:"token"`
	Error  string `json:"error"`
}

func loginCall(method, path string) (loginReply, int, error) {
	var out loginReply
	req, err := http.NewRequest(method, loginBase+path, nil)
	if err != nil {
		return out, 0, err
	}
	setDeviceHeaders(req)
	resp, err := loginClient.Do(req)
	if err != nil {
		return out, 0, fmt.Errorf("бот недоступен: %v", err)
	}
	defer resp.Body.Close()
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out, resp.StatusCode, nil
}

// POST /api/login {action: start} → {code, url};  {action: poll, code} → {status: wait|ok|denied|expired, sub}
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string `json:"action"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный запрос")
		return
	}
	switch in.Action {
	case "start":
		out, code, err := loginCall("POST", "/login/start")
		if err != nil {
			fail(w, 502, err.Error())
			return
		}
		if code != 200 || out.Code == "" || !strings.HasPrefix(out.URL, "https://t.me/") {
			msg := out.Error
			if msg == "" {
				msg = fmt.Sprintf("бот ответил %d", code)
			}
			fail(w, 502, msg)
			return
		}
		openExternal(out.URL)
		svg, _ := qrSVG(out.URL) // QR: войти можно и с телефона, отсканировав камерой
		writeJSON(w, 200, map[string]any{"code": out.Code, "url": out.URL, "svg": svg})
	case "poll":
		out, code, err := loginCall("GET", "/login/poll?code="+url.QueryEscape(in.Code))
		if err != nil {
			writeJSON(w, 200, map[string]any{"status": "wait", "note": err.Error()}) // сеть мигнула — спросим ещё раз
			return
		}
		if code == 410 {
			writeJSON(w, 200, map[string]any{"status": "expired"})
			return
		}
		if out.Status == "ok" && !strings.HasPrefix(out.Sub, "https://") && !strings.HasPrefix(out.Sub, "http://") {
			fail(w, 502, "бот прислал непонятный ответ")
			return
		}
		if out.Status == "ok" && out.Token != "" {
			a.mu.Lock()
			a.st.AppToken, a.st.ChatSeen = out.Token, 0
			st := a.st
			a.mu.Unlock()
			_ = saveSettings(a.dataDir, st)
		}
		writeJSON(w, 200, map[string]any{"status": out.Status, "sub": out.Sub, "name": out.Name})
	default:
		fail(w, 400, "неизвестное действие")
	}
}

// subNotice: подписка вместо серверов прислала одну строку-подсказку (лимит устройств, устаревшая ссылка) — её текст.
func subNotice(list []Server) string {
	if len(list) == 1 && list[0].Host == "127.0.0.1" && list[0].Port == 1 {
		n := strings.TrimSpace(list[0].Name)
		if n == "" {
			n = "сервис не отдал серверы"
		}
		return n
	}
	return ""
}
