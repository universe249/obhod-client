package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Connection history: one point per minute for the last 48 hours, hourly totals for 30 days, outage list.

type minutePoint struct {
	T  int64 `json:"t"`  // unix minute
	Ms int   `json:"ms"` // average ping of successful probes; -1 = every probe failed
}

type hourAgg struct {
	H    int64 `json:"h"` // unix hour
	N    int   `json:"n"`
	Fail int   `json:"f"`
	Sum  int64 `json:"s"`
}

type Outage struct {
	Start int64 `json:"start"` // unix seconds
	End   int64 `json:"end"`   // 0 = still going
}

type historyData struct {
	Minutes []minutePoint `json:"minutes"`
	Hours   []hourAgg     `json:"hours"`
	Outages []Outage      `json:"outages"`
}

type History struct {
	mu       sync.Mutex
	d        historyData
	path     string
	dirty    bool
	curMin   int64
	curSum   int
	curOK    int
	curFail  int
	failRun  int
	failFrom int64
	notified bool
}

func newHistory(dir string) *History {
	h := &History{path: filepath.Join(dir, "history.json")}
	if b, err := os.ReadFile(h.path); err == nil {
		_ = json.Unmarshal(b, &h.d)
	}
	return h
}

func (h *History) flushMinute() {
	if h.curMin == 0 || h.curOK+h.curFail == 0 {
		return
	}
	ms := -1
	if h.curOK > 0 {
		ms = h.curSum / h.curOK
	}
	h.d.Minutes = append(h.d.Minutes, minutePoint{h.curMin, ms})
	if len(h.d.Minutes) > 48*60 {
		h.d.Minutes = h.d.Minutes[len(h.d.Minutes)-48*60:]
	}
	h.curSum, h.curOK, h.curFail = 0, 0, 0
	h.dirty = true
}

// Record stores one probe. It returns the length of the current outage (0 if none) so the caller can warn.
func (h *History) Record(now time.Time, ok bool, ms int) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	min := now.Unix() / 60
	if min != h.curMin {
		h.flushMinute()
		h.curMin = min
	}
	hr := now.Unix() / 3600
	if n := len(h.d.Hours); n == 0 || h.d.Hours[n-1].H != hr {
		h.d.Hours = append(h.d.Hours, hourAgg{H: hr})
		if len(h.d.Hours) > 24*30 {
			h.d.Hours = h.d.Hours[len(h.d.Hours)-24*30:]
		}
	}
	ha := &h.d.Hours[len(h.d.Hours)-1]
	ha.N++
	if ok {
		h.curOK++
		h.curSum += ms
		ha.Sum += int64(ms)
		h.failRun = 0
		if n := len(h.d.Outages); n > 0 && h.d.Outages[n-1].End == 0 {
			h.d.Outages[n-1].End = now.Unix()
			h.notified = false
		}
	} else {
		h.curFail++
		ha.Fail++
		if h.failRun == 0 {
			h.failFrom = now.Unix()
		}
		h.failRun++
		n := len(h.d.Outages)
		if h.failRun >= 3 && (n == 0 || h.d.Outages[n-1].End != 0) {
			h.d.Outages = append(h.d.Outages, Outage{Start: h.failFrom})
			if len(h.d.Outages) > 200 {
				h.d.Outages = h.d.Outages[len(h.d.Outages)-200:]
			}
		}
	}
	h.dirty = true
	if n := len(h.d.Outages); n > 0 && h.d.Outages[n-1].End == 0 {
		return now.Sub(time.Unix(h.d.Outages[n-1].Start, 0))
	}
	return 0
}

// TunnelStopped closes an open outage: a stopped tunnel is not a server outage.
func (h *History) TunnelStopped(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failRun = 0
	if n := len(h.d.Outages); n > 0 && h.d.Outages[n-1].End == 0 {
		h.d.Outages[n-1].End = now.Unix()
		h.dirty = true
	}
}

func (h *History) Flush() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.dirty {
		return
	}
	h.flushMinute()
	b, err := json.Marshal(h.d)
	if err != nil {
		return
	}
	tmp := h.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil && os.Rename(tmp, h.path) == nil {
		h.dirty = false
	}
}

type dayRow struct {
	Day    string  `json:"day"`
	Uptime float64 `json:"uptime"` // percent of successful probes, -1 = no data
	AvgMs  int     `json:"avgMs"`
}

// View builds the data for the UI.
func (h *History) View(now time.Time) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	mins := append([]minutePoint(nil), h.d.Minutes...)
	if h.curOK+h.curFail > 0 {
		ms := -1
		if h.curOK > 0 {
			ms = h.curSum / h.curOK
		}
		mins = append(mins, minutePoint{h.curMin, ms})
	}
	cut := now.Add(-24*time.Hour).Unix() / 60
	var day []minutePoint
	for _, p := range mins {
		if p.T >= cut {
			day = append(day, p)
		}
	}
	type acc struct {
		n, f int
		sum  int64
	}
	byDay := map[string]*acc{}
	var total acc
	for _, ha := range h.d.Hours {
		d := time.Unix(ha.H*3600, 0).Format("2006-01-02")
		a := byDay[d]
		if a == nil {
			a = &acc{}
			byDay[d] = a
		}
		a.n += ha.N
		a.f += ha.Fail
		a.sum += ha.Sum
		total.n += ha.N
		total.f += ha.Fail
	}
	var days []dayRow
	for i := 29; i >= 0; i-- {
		d := now.AddDate(0, 0, -i).Format("2006-01-02")
		row := dayRow{Day: d, Uptime: -1}
		if a := byDay[d]; a != nil && a.n > 0 {
			row.Uptime = float64(a.n-a.f) * 100 / float64(a.n)
			if ok := a.n - a.f; ok > 0 {
				row.AvgMs = int(a.sum / int64(ok))
			}
		}
		days = append(days, row)
	}
	up := -1.0
	if total.n > 0 {
		up = float64(total.n-total.f) * 100 / float64(total.n)
	}
	outs := append([]Outage(nil), h.d.Outages...)
	sort.Slice(outs, func(i, j int) bool { return outs[i].Start > outs[j].Start })
	if len(outs) > 30 {
		outs = outs[:30]
	}
	if day == nil {
		day = []minutePoint{}
	}
	if outs == nil {
		outs = []Outage{}
	}
	return map[string]any{"minutes": day, "days": days, "outages": outs, "uptime": up, "now": now.Unix()}
}

func fmtDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d с", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	}
	return fmt.Sprintf("%d ч %d мин", int(d.Hours()), int(d.Minutes())%60)
}

func (a *App) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		a.hist.mu.Lock()
		a.hist.d = historyData{}
		a.hist.dirty = true
		a.hist.mu.Unlock()
		a.hist.Flush()
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	writeJSON(w, 200, a.hist.View(time.Now()))
}

func (a *App) historyFlushLoop() {
	for {
		select {
		case <-a.quit:
			a.hist.Flush()
			return
		case <-time.After(2 * time.Minute):
			a.hist.Flush()
		}
	}
}
