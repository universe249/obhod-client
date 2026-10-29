package main

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// hogConn is one connection as seen by the clash API at a moment.
type hogConn struct {
	ID      string
	Process string
	Host    string
	Via     string // proxy | direct
	Up      int64
	Down    int64
}

// Hog is a program's current load on the network.
type Hog struct {
	Process string  `json:"process"`
	Down    float64 `json:"down"` // bytes/s
	Up      float64 `json:"up"`
	Via     string  `json:"via"` // proxy | direct | mixed
	Conns   int     `json:"conns"`
	Host    string  `json:"host"`
}

type hogTracker struct {
	mu   sync.Mutex
	prev map[string][2]int64
	at   time.Time
}

// hogRates turns two samples of cumulative counters into per-program rates.
// A connection that was not in the previous sample counts from zero; counters that went down are ignored.
func hogRates(prev map[string][2]int64, cur []hogConn, dt float64, skip func(string) bool) []Hog {
	if dt < 0.2 {
		dt = 0.2
	}
	type acc struct {
		h         Hog
		pxy, dir  int64
		hostBytes map[string]int64
	}
	by := map[string]*acc{}
	for _, c := range cur {
		if c.Process == "" || (skip != nil && skip(c.Process)) {
			continue
		}
		key := strings.ToLower(c.Process)
		a := by[key]
		if a == nil {
			a = &acc{h: Hog{Process: c.Process}, hostBytes: map[string]int64{}}
			by[key] = a
		}
		a.h.Conns++
		var du, dd int64
		if p, ok := prev[c.ID]; ok {
			du, dd = c.Up-p[0], c.Down-p[1]
		} else {
			du, dd = c.Up, c.Down
		}
		if du < 0 {
			du = 0
		}
		if dd < 0 {
			dd = 0
		}
		a.h.Up += float64(du) / dt
		a.h.Down += float64(dd) / dt
		if c.Via == "direct" {
			a.dir += du + dd
		} else {
			a.pxy += du + dd
		}
		if c.Host != "" {
			a.hostBytes[c.Host] += du + dd
		}
	}
	out := make([]Hog, 0, len(by))
	for _, a := range by {
		switch {
		case a.pxy > 0 && a.dir > 0:
			a.h.Via = "mixed"
		case a.dir > 0:
			a.h.Via = "direct"
		case a.pxy > 0:
			a.h.Via = "proxy"
		}
		var best int64 = -1
		for h, b := range a.hostBytes {
			if b > best || (b == best && h < a.h.Host) {
				best, a.h.Host = b, h
			}
		}
		out = append(out, a.h)
	}
	sort.Slice(out, func(i, j int) bool {
		ti, tj := out[i].Down+out[i].Up, out[j].Down+out[j].Up
		if ti != tj {
			return ti > tj
		}
		return out[i].Process < out[j].Process
	})
	return out
}

func (a *App) handleHogs(w http.ResponseWriter, r *http.Request) {
	st := a.settings()
	var cn struct {
		Connections []struct {
			ID       string `json:"id"`
			Metadata struct {
				Host    string `json:"host"`
				Process string `json:"processPath"`
			} `json:"metadata"`
			Up     int64    `json:"upload"`
			Down   int64    `json:"download"`
			Chains []string `json:"chains"`
		} `json:"connections"`
	}
	if err := clashGet(st, "/connections", &cn); err != nil {
		writeJSON(w, 200, map[string]any{"hogs": []Hog{}})
		return
	}
	cur := make([]hogConn, 0, len(cn.Connections))
	for _, c := range cn.Connections {
		via := "direct"
		if len(c.Chains) > 0 {
			via = c.Chains[0]
		}
		p := c.Metadata.Process
		if i := strings.LastIndexAny(p, `\/`); i >= 0 {
			p = p[i+1:]
		}
		cur = append(cur, hogConn{ID: c.ID, Process: p, Host: c.Metadata.Host, Via: via, Up: c.Up, Down: c.Down})
	}
	t := &a.hogs
	t.mu.Lock()
	now := time.Now()
	var hogs []Hog
	if t.prev != nil && now.Sub(t.at) < 15*time.Second {
		hogs = hogRates(t.prev, cur, now.Sub(t.at).Seconds(), isOwnProcess)
	}
	t.prev = make(map[string][2]int64, len(cur))
	for _, c := range cur {
		t.prev[c.ID] = [2]int64{c.Up, c.Down}
	}
	t.at = now
	t.mu.Unlock()
	if hogs == nil {
		hogs = []Hog{}
	}
	if len(hogs) > 8 {
		hogs = hogs[:8]
	}
	// only programs that really move data
	k := 0
	for _, h := range hogs {
		if h.Down+h.Up >= 512 {
			hogs[k] = h
			k++
		}
	}
	writeJSON(w, 200, map[string]any{"hogs": hogs[:k]})
}

func isOwnProcess(p string) bool {
	p = strings.ToLower(p)
	return p == "sing-box.exe" || p == "xray.exe" || strings.HasPrefix(p, "obhod") || strings.HasPrefix(p, "обход") || p == "singui.exe"
}
