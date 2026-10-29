package main

import (
	"fmt"
	"strconv"
	"time"
)

type subAlert struct{ Key, Text string }

// subAlerts says what is worth telling the user about a subscription right now.
// At most one alert per kind (expiry, traffic), the most urgent one. Keys carry the expiry date,
// so a renewed subscription gets fresh alerts.
func subAlerts(m *SubMeta, now time.Time) []subAlert {
	if m == nil {
		return nil
	}
	var out []subAlert
	suffix := "@" + strconv.FormatInt(m.Expire, 10)
	if m.Expire > 0 {
		left := time.Unix(m.Expire, 0).Sub(now)
		switch {
		case left <= 0:
			out = append(out, subAlert{"exp0" + suffix, "Подписка закончилась. Продли её, иначе обход перестанет работать."})
		case left <= 24*time.Hour:
			out = append(out, subAlert{"exp1" + suffix, "Подписка заканчивается меньше чем через сутки."})
		case left <= 72*time.Hour:
			days := int(left.Hours()/24 + 0.999)
			out = append(out, subAlert{"exp3" + suffix, fmt.Sprintf("Подписка заканчивается через %d дн.", days)})
		}
	}
	if m.Total > 0 {
		pct := int(m.Used * 100 / m.Total)
		switch {
		case pct >= 100:
			out = append(out, subAlert{"full" + suffix, "Трафик по подписке закончился."})
		case pct >= 90:
			out = append(out, subAlert{"t90" + suffix, fmt.Sprintf("Использовано %d%% трафика по подписке.", pct)})
		}
	}
	return out
}

// checkSubAlerts notifies about every alert that was not shown yet.
func (a *App) checkSubAlerts() {
	a.mu.Lock()
	m := a.st.SubMeta
	old := a.st.SubAlerted
	a.mu.Unlock()
	alerts := subAlerts(m, time.Now())
	seen := map[string]bool{}
	for _, k := range old {
		seen[k] = true
	}
	var keys []string
	for _, al := range alerts {
		keys = append(keys, al.Key)
		if !seen[al.Key] {
			a.notify(appName, al.Text)
		}
	}
	if len(keys) == len(old) {
		same := true
		for i := range keys {
			if keys[i] != old[i] {
				same = false
			}
		}
		if same {
			return
		}
	}
	a.mu.Lock()
	a.st.SubAlerted = keys
	st := a.st
	a.mu.Unlock()
	_ = saveSettings(a.dataDir, st)
}
