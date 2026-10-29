package main

import (
	"strconv"
	"strings"
	"time"
)

// SchedRule: в указанные дни и время выполнить действие один раз.
type SchedRule struct {
	Days   []int  `json:"days"`   // 0 = воскресенье … 6 = суббота; пусто = каждый день
	Time   string `json:"time"`   // "HH:MM"
	Action string `json:"action"` // on | off | preset
	Preset string `json:"preset"` // для preset: b:smart, b:global, b:games, u:N
}

const schedMax = 12

func parseHM(s string) (h, m int, ok bool) {
	p := strings.SplitN(strings.TrimSpace(s), ":", 2)
	if len(p) != 2 {
		return 0, 0, false
	}
	h, e1 := strconv.Atoi(p[0])
	m, e2 := strconv.Atoi(p[1])
	if e1 != nil || e2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

func cleanSchedule(in []SchedRule) []SchedRule {
	var out []SchedRule
	for _, r := range in {
		h, m, ok := parseHM(r.Time)
		if !ok || len(out) >= schedMax {
			continue
		}
		if r.Action != "on" && r.Action != "off" && !(r.Action == "preset" && r.Preset != "") {
			continue
		}
		seen := map[int]bool{}
		var days []int
		for _, d := range r.Days {
			if d >= 0 && d <= 6 && !seen[d] {
				seen[d] = true
				days = append(days, d)
			}
		}
		if len(days) == 7 {
			days = nil
		}
		if r.Action != "preset" {
			r.Preset = ""
		}
		out = append(out, SchedRule{Days: days, Time: strconv.Itoa(h/10) + strconv.Itoa(h%10) + ":" + strconv.Itoa(m/10) + strconv.Itoa(m%10), Action: r.Action, Preset: r.Preset})
	}
	return out
}

// schedDue returns the rules whose time fell into (from, to]. Checking a window instead of an exact minute
// keeps a rule from being skipped when the loop is late.
func schedDue(rules []SchedRule, from, to time.Time) []int {
	if to.Sub(from) > 10*time.Minute {
		from = to.Add(-10 * time.Minute)
	}
	var due []int
	for t := from.Truncate(time.Minute).Add(time.Minute); !t.After(to); t = t.Add(time.Minute) {
		for i, r := range rules {
			h, m, ok := parseHM(r.Time)
			if !ok || h != t.Hour() || m != t.Minute() {
				continue
			}
			if len(r.Days) > 0 {
				match := false
				for _, d := range r.Days {
					if d == int(t.Weekday()) {
						match = true
					}
				}
				if !match {
					continue
				}
			}
			due = append(due, i)
		}
	}
	return due
}

func (a *App) runSched(r SchedRule) {
	switch r.Action {
	case "on":
		if !a.core.Running() {
			a.toggleTunnel(false)
			a.event("info", "По расписанию: обход включён")
		}
	case "off":
		if a.core.Running() {
			a.toggleTunnel(false)
		}
		a.setWant(false)
		a.event("info", "По расписанию: обход выключен")
	case "preset":
		if err := a.applyPresetID(r.Preset); err != nil {
			a.event("bad", "По расписанию не удалось применить набор правил: "+err.Error())
			return
		}
		if a.core.Running() {
			_ = a.restartCore()
		}
		a.event("info", "По расписанию применён набор правил")
	}
}

func (a *App) schedLoop() {
	last := time.Now()
	for {
		select {
		case <-a.quit:
			return
		case <-time.After(15 * time.Second):
		}
		now := time.Now()
		rules := a.settings().Schedule
		for _, i := range schedDue(rules, last, now) {
			a.runSched(rules[i])
		}
		last = now
	}
}
