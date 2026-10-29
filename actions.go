package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"
)

// restartCore applies the current settings to a running tunnel.
func (a *App) restartCore() error {
	a.core.Stop()
	return startedOK(a.core.Start(a.settings()))
}

// useProfile makes saved server i the active one; restarts the tunnel if it runs.
func (a *App) useProfile(i int) (string, error) {
	a.mu.Lock()
	if i < 0 || i >= len(a.st.Profiles) {
		a.mu.Unlock()
		return "", errors.New("нет такого сервера")
	}
	a.st.Server = a.st.Profiles[i]
	a.rev.Add(1)
	st := a.st
	a.mu.Unlock()
	if err := saveSettings(a.dataDir, st); err != nil {
		return "", err
	}
	name := st.Server.Name
	if name == "" {
		name = st.Server.Host
	}
	if a.core.Running() {
		if err := a.restartCore(); err != nil {
			return name, err
		}
	}
	return name, nil
}

// setGame switches game mode (selected apps go direct) and applies it.
func (a *App) setGame(on bool) error {
	a.mu.Lock()
	if len(a.st.GameApps) == 0 && on {
		a.mu.Unlock()
		return errors.New("сначала выбери игры во вкладке «Правила → Приложения»")
	}
	a.st.GameMode = on
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

func (a *App) handleGame(w http.ResponseWriter, r *http.Request) {
	var in struct {
		On bool `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	if err := a.setGame(in.On); err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "gameMode": in.On})
}

// rollbackExe swaps the running exe with its .bak (the previous version).
func rollbackExe(exe string) error {
	bak, tmp := exe+".bak", exe+".rb"
	if _, err := os.Stat(bak); err != nil {
		return errors.New("предыдущей версии нет")
	}
	_ = os.Remove(tmp)
	if err := os.Rename(exe, tmp); err != nil {
		return err
	}
	if err := os.Rename(bak, exe); err != nil {
		_ = os.Rename(tmp, exe)
		return err
	}
	_ = os.Rename(tmp, bak) // the version we leave becomes the new .bak
	return nil
}

func (a *App) doRollback(w http.ResponseWriter) {
	exe, err := os.Executable()
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	wasOn := a.core.Running() || a.wanted()
	a.core.Stop()
	if err := rollbackExe(exe); err != nil {
		if wasOn {
			_ = startedOK(a.core.Start(a.settings()))
		}
		fail(w, 500, "не удалось откатить: "+err.Error())
		return
	}
	// no -resume here: an older version does not know the flag and would refuse to start
	if err := relaunchSelf(exe, false); err != nil {
		fail(w, 500, "откачено, но не удалось перезапустить — запусти программу вручную: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "restarting": true})
	go func() {
		time.Sleep(500 * time.Millisecond)
		a.doQuit()
	}()
}

func hasRollback() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	fi, err := os.Stat(exe + ".bak")
	return err == nil && fi.Size() > 1<<20
}

// trayStateNow maps the tunnel state to a tray icon.
func (a *App) trayStateNow() int {
	if !a.core.Running() {
		return trayOff
	}
	switch h, _ := a.health.Get(); h {
	case "ok":
		return trayOn
	case "bad":
		return trayBad
	}
	return trayStarting
}
