package main

import (
	"fmt"
	"time"
)

type speedMeter struct {
	up, down int64
	t        time.Time
}

func fmtRate(bps float64) string {
	switch {
	case bps >= 1<<20:
		return fmt.Sprintf("%.1f МБ/с", bps/(1<<20))
	case bps >= 1<<10:
		return fmt.Sprintf("%.0f КБ/с", bps/(1<<10))
	}
	return fmt.Sprintf("%.0f Б/с", bps)
}

// rates turns two counter readings into bytes per second.
func (m *speedMeter) rates(up, down int64, now time.Time) (float64, float64, bool) {
	ok := !m.t.IsZero() && now.After(m.t) && up >= m.up && down >= m.down
	var ru, rd float64
	if ok {
		dt := now.Sub(m.t).Seconds()
		ru, rd = float64(up-m.up)/dt, float64(down-m.down)/dt
	}
	m.up, m.down, m.t = up, down, now
	return ru, rd, ok
}

// trayInfoNow is the second line of the tray tooltip: speed and response time of the server.
func (a *App) trayInfoNow(m *speedMeter) string {
	st := a.settings()
	if !a.core.Running() {
		m.t = time.Time{}
		return ""
	}
	var cn struct {
		Up   int64 `json:"uploadTotal"`
		Down int64 `json:"downloadTotal"`
	}
	if clashGet(st, "/connections", &cn) != nil {
		return ""
	}
	ru, rd, ok := m.rates(cn.Up, cn.Down, time.Now())
	if !ok {
		return ""
	}
	s := fmt.Sprintf("↓ %s  ↑ %s", fmtRate(rd), fmtRate(ru))
	if h, ms := a.health.Get(); h == "ok" && ms > 0 {
		s += fmt.Sprintf(" · %d мс", ms)
	}
	return s
}
