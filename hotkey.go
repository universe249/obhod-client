package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
)

const (
	modAlt   = 0x1
	modCtrl  = 0x2
	modShift = 0x4
	modWin   = 0x8
)

// hotkeyActions are what a global shortcut can do.
var hotkeyActions = []struct{ ID, Title string }{
	{"toggle", "Включить / выключить обход"},
	{"game", "Включить / выключить игровой режим"},
}

var hotkeyDefaults = map[string]string{"toggle": "Ctrl+Alt+O"}

var namedKeys = map[string]uint32{
	"SPACE": 0x20, "INSERT": 0x2D, "DELETE": 0x2E, "HOME": 0x24, "END": 0x23, "PAGEUP": 0x21, "PAGEDOWN": 0x22,
	"LEFT": 0x25, "UP": 0x26, "RIGHT": 0x27, "DOWN": 0x28, "PAUSE": 0x13,
}

// parseHotkey reads "Ctrl+Alt+O" and returns the Windows modifiers, the virtual-key code and the canonical text.
func parseHotkey(s string) (mods, vk uint32, canon string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, "", nil
	}
	var key string
	for _, p := range strings.Split(s, "+") {
		p = strings.TrimSpace(p)
		switch strings.ToUpper(p) {
		case "CTRL", "CONTROL", "CTL":
			mods |= modCtrl
		case "ALT":
			mods |= modAlt
		case "SHIFT":
			mods |= modShift
		case "WIN", "META", "SUPER", "CMD":
			mods |= modWin
		case "":
			return 0, 0, "", errors.New("пустая клавиша в сочетании")
		default:
			if key != "" {
				return 0, 0, "", errors.New("в сочетании должна быть одна обычная клавиша")
			}
			key = strings.ToUpper(p)
		}
	}
	if key == "" {
		return 0, 0, "", errors.New("добавь обычную клавишу, не только Ctrl или Alt")
	}
	switch {
	case len(key) == 1 && key[0] >= 'A' && key[0] <= 'Z':
		vk = uint32(key[0])
	case len(key) == 1 && key[0] >= '0' && key[0] <= '9':
		vk = uint32(key[0])
	case key[0] == 'F' && len(key) <= 3:
		n := 0
		for _, c := range key[1:] {
			if c < '0' || c > '9' {
				return 0, 0, "", errors.New("неизвестная клавиша «" + key + "»")
			}
			n = n*10 + int(c-'0')
		}
		if n < 1 || n > 24 {
			return 0, 0, "", errors.New("неизвестная клавиша «" + key + "»")
		}
		vk = uint32(0x6F + n)
	default:
		v, ok := namedKeys[key]
		if !ok {
			return 0, 0, "", errors.New("неизвестная клавиша «" + key + "»")
		}
		vk = v
	}
	if mods == 0 {
		return 0, 0, "", errors.New("нужна хотя бы одна из клавиш Ctrl, Alt, Shift или Win")
	}
	if mods&(modAlt|modWin) == 0 && mods&modCtrl != 0 && mods&modShift == 0 {
		return 0, 0, "", errors.New("Ctrl с одной клавишей перехватил бы привычные сочетания (Ctrl+C и т. п.): добавь Alt или Shift")
	}
	if mods == modShift {
		return 0, 0, "", errors.New("Shift с одной клавишей мешал бы печатать: добавь Ctrl или Alt")
	}
	if mods == modCtrl|modAlt && key == "DELETE" {
		return 0, 0, "", errors.New("Ctrl+Alt+Del занято Windows")
	}
	var parts []string
	if mods&modCtrl != 0 {
		parts = append(parts, "Ctrl")
	}
	if mods&modAlt != 0 {
		parts = append(parts, "Alt")
	}
	if mods&modShift != 0 {
		parts = append(parts, "Shift")
	}
	if mods&modWin != 0 {
		parts = append(parts, "Win")
	}
	name := key
	if len(key) > 1 && key[0] != 'F' {
		name = key[:1] + strings.ToLower(key[1:])
	} else if key[0] == 'F' && len(key) <= 3 {
		name = key
	}
	return mods, vk, strings.Join(append(parts, name), "+"), nil
}

// cleanHotkeys validates the map and returns canonical shortcuts; two actions cannot share one.
func cleanHotkeys(in map[string]string) (map[string]string, error) {
	out := map[string]string{}
	used := map[string]string{}
	for _, act := range hotkeyActions {
		v := strings.TrimSpace(in[act.ID])
		_, _, canon, err := parseHotkey(v)
		if err != nil {
			return nil, errors.New(act.Title + ": " + err.Error())
		}
		if canon == "" {
			out[act.ID] = ""
			continue
		}
		if other, dup := used[canon]; dup {
			return nil, errors.New("сочетание " + canon + " уже назначено: " + other)
		}
		used[canon] = act.Title
		out[act.ID] = canon
	}
	return out, nil
}

// hotkeyHost registers global shortcuts (Windows) and reports which of them are taken by other programs.
type hotkeyHost struct {
	mu     sync.Mutex
	status map[string]string // action -> "" (ok) or a reason
}

func (h *hotkeyHost) setStatus(m map[string]string) {
	h.mu.Lock()
	h.status = m
	h.mu.Unlock()
}

func (h *hotkeyHost) getStatus() map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]string{}
	for k, v := range h.status {
		out[k] = v
	}
	return out
}

// applyHotkeys (re)registers shortcuts for the current settings.
func (a *App) applyHotkeys() {
	st := a.settings()
	binds := map[string][2]uint32{}
	for id, txt := range st.Hotkeys {
		if m, vk, _, err := parseHotkey(txt); err == nil && vk != 0 {
			binds[id] = [2]uint32{m, vk}
		}
	}
	a.hk.setStatus(hotkeyRegister(binds, a.onHotkey))
}

func (a *App) onHotkey(action string) {
	switch action {
	case "toggle":
		a.toggleTunnel(true)
	case "game":
		a.toggleGame()
	}
}

func (a *App) handleHotkeys(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var in struct {
			Hotkeys map[string]string `json:"hotkeys"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			fail(w, 400, "неверный JSON")
			return
		}
		clean, err := cleanHotkeys(in.Hotkeys)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		a.mu.Lock()
		a.st.Hotkeys = clean
		a.rev.Add(1)
		st := a.st
		a.mu.Unlock()
		if err := saveSettings(a.dataDir, st); err != nil {
			fail(w, 500, err.Error())
			return
		}
		a.applyHotkeys()
	}
	acts := make([]map[string]string, 0, len(hotkeyActions))
	for _, x := range hotkeyActions {
		acts = append(acts, map[string]string{"id": x.ID, "title": x.Title})
	}
	writeJSON(w, 200, map[string]any{"hotkeys": a.settings().Hotkeys, "status": a.hk.getStatus(), "actions": acts, "defaults": hotkeyDefaults})
}
