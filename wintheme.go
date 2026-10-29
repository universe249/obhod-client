package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
)

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// parseHex turns "#rrggbb" into a Windows COLORREF (0x00BBGGRR).
func parseHex(s string) (uint32, bool) {
	if !hexColor.MatchString(s) {
		return 0, false
	}
	n, err := strconv.ParseUint(s[1:], 16, 32)
	if err != nil {
		return 0, false
	}
	r, g, b := uint32(n>>16)&0xff, uint32(n>>8)&0xff, uint32(n)&0xff
	return b<<16 | g<<8 | r, true
}

// POST /api/wintheme {dark, bg, text, border}: recolours the title bar of the app window to match the theme.
func (a *App) handleWinTheme(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Dark   bool   `json:"dark"`
		Bg     string `json:"bg"`
		Text   string `json:"text"`
		Border string `json:"border"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	bg, ok1 := parseHex(in.Bg)
	tx, ok2 := parseHex(in.Text)
	bd, ok3 := parseHex(in.Border)
	if !ok1 || !ok2 || !ok3 {
		fail(w, 400, "неверный цвет")
		return
	}
	n := themeAppWindow(in.Dark, bg, tx, bd)
	writeJSON(w, 200, map[string]any{"ok": true, "windows": n})
}
