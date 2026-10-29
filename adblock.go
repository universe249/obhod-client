package main

import (
	"encoding/json"
	"net/http"
)

// POST /api/adblock {"on": true, "allow": ["site.ru"]} — включить или выключить блокировку рекламы и задать исключения.
// Если туннель работает, он перезапускается (список рекламы при этом скачивается сам, если его ещё нет).
func (a *App) handleAdBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		st := a.settings()
		writeJSON(w, 200, map[string]any{"on": st.AdBlock, "allow": st.AdAllow})
		return
	}
	var in struct {
		On    bool      `json:"on"`
		Allow *[]string `json:"allow"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	a.mu.Lock()
	a.st.AdBlock = in.On
	if in.Allow != nil {
		a.st.AdAllow = cleanList(*in.Allow, normDomain)
	}
	a.rev.Add(1)
	st := a.st
	a.mu.Unlock()
	if err := saveSettings(a.dataDir, st); err != nil {
		fail(w, 500, err.Error())
		return
	}
	if st.AdBlock && !validSRS(ruleSetPath(a.dataDir, adsTag)) {
		// скачиваем список заранее, пока туннель ещё работает (после остановки GitHub может быть недоступен)
		if err := downloadRuleSet(a.dataDir, ruleSetFor(adsTag)); err != nil {
			fail(w, 502, "Не удалось скачать список рекламы: "+err.Error()+". Попробуй ещё раз чуть позже.")
			a.mu.Lock()
			a.st.AdBlock = false
			st = a.st
			a.mu.Unlock()
			_ = saveSettings(a.dataDir, st)
			return
		}
	}
	if a.core.Running() {
		if err := a.restartCore(); err != nil {
			fail(w, 500, "Настройка сохранена, но туннель не перезапустился: "+err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "on": st.AdBlock, "allow": st.AdAllow})
}
