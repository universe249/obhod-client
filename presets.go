package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Preset is a saved set of rules: which mode, which services, which apps.
type Preset struct {
	Name       string          `json:"name"`
	Mode       string          `json:"mode"`
	Services   map[string]bool `json:"services"`
	BlockedRU  bool            `json:"blockedRu"`
	GameMode   bool            `json:"gameMode"`
	ProxyApps  []string        `json:"proxyApps"`
	DirectApps []string        `json:"directApps"`
}

type presetView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Note    string `json:"note"`
	Builtin bool   `json:"builtin"`
	Active  bool   `json:"active"`
}

func isGlobal(st Settings) bool { return st.Mode == "global" }

func sameSet(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	for i := range x {
		x[i] = strings.ToLower(x[i])
	}
	for i := range y {
		y[i] = strings.ToLower(y[i])
	}
	sort.Strings(x)
	sort.Strings(y)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func sameServices(a, b map[string]bool) bool {
	for k, v := range a {
		if v && !b[k] {
			return false
		}
	}
	for k, v := range b {
		if v && !a[k] {
			return false
		}
	}
	return true
}

func presetMatches(st Settings, p Preset) bool {
	mode := p.Mode
	if mode == "" {
		mode = "smart"
	}
	cur := st.Mode
	if cur == "" {
		cur = "smart"
	}
	return mode == cur && p.BlockedRU == st.BlockedRU && p.GameMode == st.GameMode &&
		sameServices(p.Services, st.Services) && sameSet(p.ProxyApps, st.ProxyApps) && sameSet(p.DirectApps, st.DirectApps)
}

func snapshotPreset(name string, st Settings) Preset {
	svc := map[string]bool{}
	for k, v := range st.Services {
		if v {
			svc[k] = true
		}
	}
	mode := st.Mode
	if mode == "" {
		mode = "smart"
	}
	return Preset{Name: name, Mode: mode, Services: svc, BlockedRU: st.BlockedRU, GameMode: st.GameMode,
		ProxyApps: append([]string(nil), st.ProxyApps...), DirectApps: append([]string(nil), st.DirectApps...)}
}

func applyPreset(st *Settings, p Preset) {
	st.Mode = p.Mode
	st.BlockedRU = p.BlockedRU
	st.GameMode = p.GameMode
	st.Services = map[string]bool{}
	for k, v := range p.Services {
		if v {
			st.Services[k] = true
		}
	}
	st.ProxyApps = append([]string(nil), p.ProxyApps...)
	st.DirectApps = append([]string(nil), p.DirectApps...)
}

// builtinPresets change only the mode, everything else (your services and apps) stays.
func presetViews(st Settings) []presetView {
	global := isGlobal(st)
	out := []presetView{
		{ID: "b:smart", Name: "Обычный", Note: "Через сервер только заблокированное и выбранные сервисы", Builtin: true, Active: !global && !st.GameMode},
		{ID: "b:global", Name: "Всё через сервер", Note: "Весь трафик, кроме российских сайтов и твоих исключений", Builtin: true, Active: global},
		{ID: "b:games", Name: "Игры", Note: "Обычный режим, а игры из списка идут напрямую (меньше пинг)", Builtin: true, Active: !global && st.GameMode},
	}
	for i, p := range st.Presets {
		out = append(out, presetView{ID: "u:" + itoa(i), Name: p.Name, Note: presetNote(p), Active: presetMatches(st, p)})
	}
	return out
}

func presetNote(p Preset) string {
	n := 0
	for _, v := range p.Services {
		if v {
			n++
		}
	}
	mode := "обычный режим"
	if p.Mode == "global" {
		mode = "всё через сервер"
	}
	s := mode + ", сервисов: " + itoa(n)
	if p.GameMode {
		s += ", игровой режим"
	}
	return s
}

func (a *App) applyPresetID(id string) error {
	a.mu.Lock()
	switch {
	case id == "b:smart":
		a.st.Mode, a.st.GameMode = "smart", false
		a.st.BlockedRU = true
	case id == "b:global":
		a.st.Mode, a.st.GameMode = "global", false
	case id == "b:games":
		if len(a.st.GameApps) == 0 {
			a.mu.Unlock()
			return errors.New("сначала выбери игры во вкладке «Правила → Приложения»")
		}
		a.st.Mode, a.st.GameMode = "smart", true
	case strings.HasPrefix(id, "u:"):
		i := -1
		for k := range a.st.Presets {
			if "u:"+itoa(k) == id {
				i = k
			}
		}
		if i < 0 {
			a.mu.Unlock()
			return errors.New("нет такого набора")
		}
		applyPreset(&a.st, a.st.Presets[i])
	default:
		a.mu.Unlock()
		return errors.New("неизвестный набор")
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

func (a *App) handlePresets(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"presets": presetViews(a.settings())})
		return
	}
	var in struct {
		Action string `json:"action"`
		ID     string `json:"id"`
		Name   string `json:"name"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	switch in.Action {
	case "apply":
		if err := a.applyPresetID(in.ID); err != nil {
			fail(w, 400, err.Error())
			return
		}
		a.event("ok", "Набор правил применён")
	case "save":
		name := strings.TrimSpace(in.Name)
		if name == "" {
			fail(w, 400, "дай набору название")
			return
		}
		if len([]rune(name)) > 40 {
			name = string([]rune(name)[:40])
		}
		a.mu.Lock()
		p := snapshotPreset(name, a.st)
		replaced := false
		for i := range a.st.Presets {
			if strings.EqualFold(a.st.Presets[i].Name, name) {
				a.st.Presets[i], replaced = p, true
			}
		}
		if !replaced {
			if len(a.st.Presets) >= 12 {
				a.mu.Unlock()
				fail(w, 400, "можно хранить не больше 12 наборов")
				return
			}
			a.st.Presets = append(a.st.Presets, p)
		}
		st := a.st
		a.mu.Unlock()
		if err := saveSettings(a.dataDir, st); err != nil {
			fail(w, 500, err.Error())
			return
		}
	case "export":
		st := a.settings()
		var p Preset
		switch {
		case strings.HasPrefix(in.ID, "u:"):
			ok := false
			for k := range st.Presets {
				if "u:"+itoa(k) == in.ID {
					p, ok = st.Presets[k], true
				}
			}
			if !ok {
				fail(w, 400, "нет такого набора")
				return
			}
		default:
			p = snapshotPreset("Мой набор", st)
		}
		code, err := presetCode(p)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "code": code})
		return
	case "import":
		p, err := parsePresetCode(in.Code)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		a.mu.Lock()
		if len(a.st.Presets) >= 12 {
			a.mu.Unlock()
			fail(w, 400, "можно хранить не больше 12 наборов — удали ненужный")
			return
		}
		base, n := p.Name, 1
		for taken := true; taken; {
			taken = false
			for _, q := range a.st.Presets {
				if strings.EqualFold(q.Name, p.Name) {
					taken = true
				}
			}
			if taken {
				n++
				p.Name = base + " (" + itoa(n) + ")"
			}
		}
		a.st.Presets = append(a.st.Presets, p)
		st := a.st
		a.mu.Unlock()
		if err := saveSettings(a.dataDir, st); err != nil {
			fail(w, 500, err.Error())
			return
		}
		a.event("ok", "Добавлен набор правил «"+p.Name+"»")
	case "delete":
		a.mu.Lock()
		i := -1
		for k := range a.st.Presets {
			if "u:"+itoa(k) == in.ID {
				i = k
			}
		}
		if i < 0 {
			a.mu.Unlock()
			fail(w, 400, "нет такого набора")
			return
		}
		a.st.Presets = append(a.st.Presets[:i:i], a.st.Presets[i+1:]...)
		a.st.Schedule = reindexSchedule(a.st.Schedule, i)
		st := a.st
		a.mu.Unlock()
		if err := saveSettings(a.dataDir, st); err != nil {
			fail(w, 500, err.Error())
			return
		}
	default:
		fail(w, 400, "неизвестное действие")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "presets": presetViews(a.settings())})
}

// reindexSchedule keeps schedule rules pointing at the right saved set after set number i was deleted:
// rules for the deleted set are dropped, later sets move one place down.
func reindexSchedule(rules []SchedRule, i int) []SchedRule {
	var out []SchedRule
	for _, r := range rules {
		if r.Action == "preset" && strings.HasPrefix(r.Preset, "u:") {
			k, err := strconv.Atoi(r.Preset[2:])
			if err == nil {
				if k == i {
					continue
				}
				if k > i {
					r.Preset = "u:" + itoa(k-1)
				}
			}
		}
		out = append(out, r)
	}
	return out
}
