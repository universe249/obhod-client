package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Traffic statistics: bytes per day, split by application and by site, direct vs through the server.

type bucket struct {
	ProxyUp, ProxyDown, DirectUp, DirectDown int64
}

type statsData struct {
	Days map[string]*dayStats `json:"days"`
}

type dayStats struct {
	Total bucket             `json:"total"`
	Apps  map[string]*bucket `json:"apps"`
	Sites map[string]*bucket `json:"sites"`
}

type Stats struct {
	mu    sync.Mutex
	data  statsData
	seen  map[string][2]int64 // connection id -> bytes counted so far
	path  string
	dirty bool
}

func newStats(dir string) *Stats {
	s := &Stats{path: filepath.Join(dir, "stats.json"), seen: map[string][2]int64{}}
	s.data.Days = map[string]*dayStats{}
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, &s.data)
		if s.data.Days == nil {
			s.data.Days = map[string]*dayStats{}
		}
	}
	return s
}

func (b *bucket) add(proxied bool, up, down int64) {
	if proxied {
		b.ProxyUp += up
		b.ProxyDown += down
	} else {
		b.DirectUp += up
		b.DirectDown += down
	}
}

// siteKey reduces a host to its registrable-ish name (last two labels).
func siteKey(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 || strings.Count(host, ":") > 0 || (len(parts) == 4 && parts[3] != "" && parts[3][0] >= '0' && parts[3][0] <= '9') {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

type connSample struct {
	ID      string
	Process string
	Host    string
	Proxied bool
	Up      int64
	Down    int64
}

// Record folds one poll of /connections into the counters (counts only the growth since the last poll).
func (s *Stats) Record(now time.Time, conns []connSample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	day := now.Format("2006-01-02")
	ds := s.data.Days[day]
	if ds == nil {
		ds = &dayStats{Apps: map[string]*bucket{}, Sites: map[string]*bucket{}}
		s.data.Days[day] = ds
	}
	cur := map[string][2]int64{}
	for _, c := range conns {
		prev := s.seen[c.ID]
		du, dd := c.Up-prev[0], c.Down-prev[1]
		cur[c.ID] = [2]int64{c.Up, c.Down}
		if du < 0 || dd < 0 || (du == 0 && dd == 0) {
			continue
		}
		ds.Total.add(c.Proxied, du, dd)
		if c.Process != "" {
			if ds.Apps[c.Process] == nil {
				ds.Apps[c.Process] = &bucket{}
			}
			ds.Apps[c.Process].add(c.Proxied, du, dd)
		}
		if k := siteKey(c.Host); k != "" {
			if ds.Sites[k] == nil {
				ds.Sites[k] = &bucket{}
			}
			ds.Sites[k].add(c.Proxied, du, dd)
		}
		s.dirty = true
	}
	s.seen = cur
	// keep 31 days, and cap per-day maps
	if len(s.data.Days) > 31 {
		var keys []string
		for k := range s.data.Days {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[:len(keys)-31] {
			delete(s.data.Days, k)
		}
	}
	for _, m := range []map[string]*bucket{ds.Apps, ds.Sites} {
		if len(m) > 400 {
			trim(m, 300)
		}
	}
}

func (b *bucket) sum() int64 { return b.ProxyUp + b.ProxyDown + b.DirectUp + b.DirectDown }

func trim(m map[string]*bucket, keep int) {
	type kv struct {
		k string
		v int64
	}
	var all []kv
	for k, v := range m {
		all = append(all, kv{k, v.sum()})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	for _, e := range all[keep:] {
		delete(m, e.k)
	}
}

func (s *Stats) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return
	}
	b, err := json.Marshal(s.data)
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil && os.Rename(tmp, s.path) == nil {
		s.dirty = false
	}
}

type topRow struct {
	Name string `json:"name"`
	bucket
}

// View summarises the last n days (n>=1).
func (s *Stats) View(now time.Time, n int) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	type dayRow struct {
		Day string `json:"day"`
		bucket
	}
	var days []dayRow
	apps, sites := map[string]*bucket{}, map[string]*bucket{}
	var total bucket
	for i := n - 1; i >= 0; i-- {
		day := now.AddDate(0, 0, -i).Format("2006-01-02")
		d := s.data.Days[day]
		row := dayRow{Day: day}
		if d != nil {
			row.bucket = d.Total
			total.ProxyUp += d.Total.ProxyUp
			total.ProxyDown += d.Total.ProxyDown
			total.DirectUp += d.Total.DirectUp
			total.DirectDown += d.Total.DirectDown
			for k, v := range d.Apps {
				if apps[k] == nil {
					apps[k] = &bucket{}
				}
				apps[k].ProxyUp, apps[k].ProxyDown = apps[k].ProxyUp+v.ProxyUp, apps[k].ProxyDown+v.ProxyDown
				apps[k].DirectUp, apps[k].DirectDown = apps[k].DirectUp+v.DirectUp, apps[k].DirectDown+v.DirectDown
			}
			for k, v := range d.Sites {
				if sites[k] == nil {
					sites[k] = &bucket{}
				}
				sites[k].ProxyUp, sites[k].ProxyDown = sites[k].ProxyUp+v.ProxyUp, sites[k].ProxyDown+v.ProxyDown
				sites[k].DirectUp, sites[k].DirectDown = sites[k].DirectUp+v.DirectUp, sites[k].DirectDown+v.DirectDown
			}
		}
		days = append(days, row)
	}
	top := func(m map[string]*bucket, limit int) []topRow {
		var rows []topRow
		for k, v := range m {
			rows = append(rows, topRow{k, *v})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].sum() > rows[j].sum() })
		if len(rows) > limit {
			rows = rows[:limit]
		}
		if rows == nil {
			rows = []topRow{}
		}
		return rows
	}
	return map[string]any{"days": days, "total": total, "apps": top(apps, 15), "sites": top(sites, 15)}
}

func (s *Stats) Reset() {
	s.mu.Lock()
	s.data.Days = map[string]*dayStats{}
	s.seen = map[string][2]int64{}
	s.dirty = true
	s.mu.Unlock()
	s.Flush()
}

// collect polls /connections every 5 seconds while the tunnel runs.
func (a *App) collectStats() {
	flushAt := time.Now()
	for {
		select {
		case <-a.quit:
			a.stats.Flush()
			return
		case <-time.After(5 * time.Second):
		}
		if !a.core.Running() {
			continue
		}
		st := a.settings()
		var cn struct {
			Connections []struct {
				ID       string `json:"id"`
				Metadata struct {
					Host    string `json:"host"`
					DestIP  string `json:"destinationIP"`
					Port    string `json:"destinationPort"`
					Process string `json:"processPath"`
				} `json:"metadata"`
				Up     int64     `json:"upload"`
				Down   int64     `json:"download"`
				Chains []string  `json:"chains"`
				Start  time.Time `json:"start"`
			} `json:"connections"`
		}
		if clashGet(st, "/connections", &cn) != nil {
			continue
		}
		obs := make([]connObs, 0, len(cn.Connections))
		list := make([]connSample, 0, len(cn.Connections))
		for _, c := range cn.Connections {
			proc := c.Metadata.Process
			if i := strings.LastIndexAny(proc, `\/`); i >= 0 {
				proc = proc[i+1:]
			}
			host := c.Metadata.Host
			if host == "" {
				host = c.Metadata.DestIP
			}
			proxied := false
			for _, ch := range c.Chains {
				if ch == "proxy" {
					proxied = true
				}
			}
			list = append(list, connSample{c.ID, proc, host, proxied, c.Up, c.Down})
			direct := len(c.Chains) > 0 && c.Chains[len(c.Chains)-1] == "direct"
			obs = append(obs, connObs{ID: c.ID, Host: c.Metadata.Host, Port: c.Metadata.Port, Direct: direct, Up: c.Up, Down: c.Down, Started: c.Start})
		}
		a.stats.Record(time.Now(), list)
		if st.Suggest && !effectiveGlobal(st, time.Now()) {
			skip := suspectSkip(st)
			for _, site := range a.suspects.observe(time.Now(), obs) {
				if !skip(site) {
					a.notify(appName, "Похоже, сайт "+site+" не открывается напрямую. Открой программу: на главной можно одной кнопкой пустить его через сервер.")
				}
			}
		}
		if time.Since(flushAt) > time.Minute {
			a.stats.Flush()
			flushAt = time.Now()
		}
	}
}

func (a *App) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		a.stats.Reset()
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	n := 7
	if r.URL.Query().Get("days") == "1" {
		n = 1
	} else if r.URL.Query().Get("days") == "30" {
		n = 30
	}
	writeJSON(w, 200, a.stats.View(time.Now(), n))
}
