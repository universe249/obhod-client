package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const backupKeep = 8

func backupDir(dataDir string) string { return filepath.Join(dataDir, "backups") }

type backupInfo struct {
	Name string    `json:"name"`
	Time time.Time `json:"time"`
	Size int64     `json:"size"`
}

func listBackups(dataDir string) []backupInfo {
	ents, _ := os.ReadDir(backupDir(dataDir))
	res := []backupInfo{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "settings-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if fi, err := e.Info(); err == nil {
			res = append(res, backupInfo{e.Name(), fi.ModTime(), fi.Size()})
		}
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Time.After(res[j].Time) })
	return res
}

// makeBackup copies settings.json (as stored, secrets stay encrypted) into data/backups.
func makeBackup(dataDir string, now time.Time) (string, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "settings.json"))
	if err != nil {
		return "", err
	}
	dir := backupDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := "settings-" + now.Format("2006-01-02-150405") + ".json"
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		return "", err
	}
	list := listBackups(dataDir)
	for i := backupKeep; i < len(list); i++ {
		_ = os.Remove(filepath.Join(dir, list[i].Name))
	}
	return name, nil
}

// backupDue reports whether the newest backup is older than a week (or missing).
func backupDue(dataDir string, now time.Time) bool {
	l := listBackups(dataDir)
	return len(l) == 0 || now.Sub(l[0].Time) >= 7*24*time.Hour
}

func (a *App) backupLoop() {
	time.Sleep(40 * time.Second)
	for {
		if backupDue(a.dataDir, time.Now()) {
			if name, err := makeBackup(a.dataDir, time.Now()); err != nil {
				logf("backup: %v", err)
			} else {
				logf("backup: %s", name)
			}
		}
		select {
		case <-a.quit:
			return
		case <-time.After(6 * time.Hour):
		}
	}
}

// GET lists backups; POST {action: create|restore, name}.
func (a *App) handleBackups(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"backups": listBackups(a.dataDir)})
		return
	}
	var in struct {
		Action string `json:"action"`
		Name   string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	switch in.Action {
	case "create":
		if _, err := makeBackup(a.dataDir, time.Now()); err != nil {
			fail(w, 500, err.Error())
			return
		}
	case "restore":
		if in.Name != filepath.Base(in.Name) || !strings.HasPrefix(in.Name, "settings-") {
			fail(w, 400, "неверное имя копии")
			return
		}
		b, err := os.ReadFile(filepath.Join(backupDir(a.dataDir), in.Name))
		if err != nil {
			fail(w, 404, "копия не найдена")
			return
		}
		var probe map[string]any
		if json.Unmarshal(b, &probe) != nil {
			fail(w, 400, "файл копии повреждён")
			return
		}
		// keep a copy of the current state before replacing it
		_, _ = makeBackup(a.dataDir, time.Now())
		restored := decodeSettings(b)
		a.mu.Lock()
		restored.APISecret = a.st.APISecret // the running core uses this one
		restored.UIPort, restored.APIPort = a.st.UIPort, a.st.APIPort
		a.st = restored
		a.rev.Add(1)
		a.mu.Unlock()
		if err := saveSettings(a.dataDir, restored); err != nil {
			fail(w, 500, err.Error())
			return
		}
	default:
		fail(w, 400, "неизвестное действие")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "backups": listBackups(a.dataDir)})
}
