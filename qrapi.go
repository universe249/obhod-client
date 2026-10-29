package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// POST /api/qr {kind:"sub"|"server"|"current", index} → {svg, link, name}
func (a *App) handleQR(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind  string `json:"kind"`
		Index int    `json:"index"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	st := a.settings()
	var link, name string
	switch in.Kind {
	case "sub":
		link, name = strings.TrimSpace(st.SubURL), "Подписка"
		if link == "" {
			fail(w, 400, "адрес подписки не задан")
			return
		}
	case "server":
		if in.Index < 0 || in.Index >= len(st.Profiles) {
			fail(w, 400, "нет такого сервера")
			return
		}
		link, name = serverLink(st.Profiles[in.Index]), st.Profiles[in.Index].Name
	default:
		if st.Server.Host == "" {
			fail(w, 400, "сервер не выбран")
			return
		}
		link, name = serverLink(st.Server), st.Server.Name
	}
	if link == "" {
		fail(w, 400, "для этого типа сервера ссылку собрать нельзя")
		return
	}
	svg, err := qrSVG(link)
	if err != nil {
		fail(w, 400, "ссылка слишком длинная для QR — скопируй её текстом")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "svg": svg, "link": link, "name": name})
}
