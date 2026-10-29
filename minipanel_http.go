package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// handleMini отдаёт страницу мини-панели (тот же вход по метке, что у главного окна).
func (a *App) handleMini(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !(strings.HasPrefix(host, "127.0.0.1:") || strings.HasPrefix(host, "localhost:")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if t := r.URL.Query().Get("t"); t != "" && t == a.token {
		http.SetCookie(w, &http.Cookie{Name: "singui", Value: a.token, Path: "/", HttpOnly: true,
			SameSite: http.SameSiteStrictMode, MaxAge: 86400 * 365})
		http.Redirect(w, r, "/mini", http.StatusFound)
		return
	}
	if ck, err := r.Cookie("singui"); err != nil || ck.Value != a.token {
		http.Error(w, "нет доступа", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(bytes.ReplaceAll(miniHTML, []byte("{{VERSION}}"), []byte("v"+appVersion)))
}

type wvRect struct{ Left, Top, Right, Bottom int32 }

// miniPlace: панель над курсором по центру; если не помещается — прижимаем к краям рабочей области
// (так она встаёт правильно и при панели задач снизу, и сверху, и сбоку).
func miniPlace(cx, cy, w, h int32, work wvRect, gap int32) (int32, int32) {
	x, y := cx-w/2, cy-h-gap
	if x+w > work.Right-gap {
		x = work.Right - gap - w
	}
	if x < work.Left+gap {
		x = work.Left + gap
	}
	if y < work.Top+gap {
		y = work.Top + gap
	}
	if y+h > work.Bottom-gap {
		y = work.Bottom - gap - h
	}
	return x, y
}

// POST /api/minilog {"ev": "..."} — панель пишет в журнал программы, что с ней происходит (нажатия, ошибки).
// Нужно, чтобы разобраться, если на каком-то компьютере панель не реагирует на мышь.
func (a *App) handleMiniLog(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ev string `json:"ev"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&in); err == nil && in.Ev != "" {
		if len(in.Ev) > 300 {
			in.Ev = in.Ev[:300]
		}
		log.Printf("мини-панель (страница): %s", in.Ev)
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
