package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// «Всё через сервер на время»: когда сайт не открывается, а разбираться некогда. Режим «умный» в настройках
// не меняется — программа сама вернётся к нему, когда время выйдет (и после перезапуска компьютера тоже).

const tempGlobalDefault = time.Hour

// effectiveGlobal: весь трафик через сервер — выбран такой режим или включено «на время».
func effectiveGlobal(st Settings, now time.Time) bool {
	return st.Mode == "global" || st.GlobalUntil > now.Unix()
}

// tempGlobalLeft: сколько секунд осталось «всего через сервер на время» (0 — не включено или режим и так «всё»).
func tempGlobalLeft(st Settings, now time.Time) int64 {
	if st.Mode == "global" || st.GlobalUntil <= now.Unix() {
		return 0
	}
	return st.GlobalUntil - now.Unix()
}

// setTempGlobal включает (d > 0) или выключает (d == 0) режим на время и применяет его к туннелю.
func (a *App) setTempGlobal(d time.Duration) error {
	a.mu.Lock()
	if d > 0 {
		a.st.GlobalUntil = time.Now().Add(d).Unix()
	} else {
		a.st.GlobalUntil = 0
	}
	a.rev.Add(1)
	st := a.st
	a.mu.Unlock()
	if err := saveSettings(a.dataDir, st); err != nil {
		return err
	}
	if a.core.Running() {
		return a.restartCore()
	}
	return nil
}

// toggleTempGlobal — для меню значка в трее и мини-панели.
func (a *App) toggleTempGlobal() {
	st := a.settings()
	if st.Mode == "global" {
		a.notify(appName, "Уже включено «Всё через сервер».")
		return
	}
	if tempGlobalLeft(st, time.Now()) > 0 {
		if err := a.setTempGlobal(0); err != nil {
			a.notify(appName, err.Error())
			return
		}
		a.notify(appName, "Снова умный режим: через сервер только заблокированное.")
		return
	}
	if err := a.setTempGlobal(tempGlobalDefault); err != nil {
		a.notify(appName, err.Error())
		return
	}
	a.notify(appName, "Весь трафик идёт через сервер. Через час программа сама вернётся в умный режим.")
}

// tempGlobalLoop возвращает умный режим, когда время вышло (проверка раз в 15 секунд).
func (a *App) tempGlobalLoop() {
	for {
		select {
		case <-a.quit:
			return
		case <-time.After(15 * time.Second):
		}
		st := a.settings()
		if st.GlobalUntil == 0 || st.GlobalUntil > time.Now().Unix() {
			continue
		}
		if err := a.setTempGlobal(0); err != nil {
			continue
		}
		if st.Mode != "global" {
			a.notify(appName, "Час прошёл: снова умный режим, через сервер только заблокированное.")
		}
	}
}

// POST /api/tempglobal {"minutes": 60} — включить; {"minutes": 0} — выключить.
func (a *App) handleTempGlobal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 200, map[string]any{"left": tempGlobalLeft(a.settings(), time.Now())})
		return
	}
	var in struct {
		Minutes int `json:"minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Minutes < 0 || in.Minutes > 24*60 {
		fail(w, 400, "неверное время")
		return
	}
	if err := a.setTempGlobal(time.Duration(in.Minutes) * time.Minute); err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "left": tempGlobalLeft(a.settings(), time.Now())})
}
