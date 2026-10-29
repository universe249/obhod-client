package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// srvStats remembers how each server behaved in each network at each time of day.
type srvCell struct {
	OK   int   `json:"ok"`
	Fail int   `json:"fail"`
	Ms   int64 `json:"ms"` // sum of latencies of successful checks
}

type srvStats struct {
	mu    sync.Mutex
	path  string
	M     map[string]*srvCell `json:"cells"`
	dirty bool
}

func newSrvStats(dir string) *srvStats {
	s := &srvStats{path: filepath.Join(dir, "srvstats.json"), M: map[string]*srvCell{}}
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, s)
		if s.M == nil {
			s.M = map[string]*srvCell{}
		}
	}
	return s
}

func srvID(s Server) string { return s.Type + "|" + s.Host + ":" + itoa(s.Port) }

// bucketOf splits the day into four parts: night, morning, day, evening.
func bucketOf(t time.Time) int { return t.Hour() / 6 }

func statKey(net string, bucket int, id string) string { return net + "/" + itoa(bucket) + "/" + id }

func (s *srvStats) record(net string, bucket int, id string, ok bool, ms int) {
	if s == nil {
		return
	}
	if net == "" || id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := statKey(net, bucket, id)
	c := s.M[k]
	if c == nil {
		if len(s.M) > 600 {
			return
		}
		c = &srvCell{}
		s.M[k] = c
	}
	if ok {
		c.OK++
		c.Ms += int64(ms)
	} else {
		c.Fail++
	}
	if c.OK+c.Fail > 400 { // старое постепенно забываем
		c.OK, c.Fail, c.Ms = c.OK/2, c.Fail/2, c.Ms/2
	}
	s.dirty = true
}

const minSamples = 8

// score is the smoothed success rate; n is how many checks stand behind it.
func (s *srvStats) score(net string, bucket int, id string) (score float64, n int) {
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.M[statKey(net, bucket, id)]
	if c == nil {
		return 0, 0
	}
	n = c.OK + c.Fail
	return float64(c.OK+1) / float64(n+2), n
}

// best returns the index of the server that clearly beats the current one here and now.
func (s *srvStats) best(list []Server, cur Server, net string, bucket int) (int, bool) {
	curID := srvID(cur)
	cs, cn := s.score(net, bucket, curID)
	bi, bs := -1, 0.0
	for i, p := range list {
		if srvID(p) == curID || p.Gone {
			continue
		}
		sc, n := s.score(net, bucket, srvID(p))
		if n >= minSamples && sc > bs {
			bi, bs = i, sc
		}
	}
	if bi < 0 {
		return -1, false
	}
	if cn >= minSamples && bs >= cs+0.2 {
		return bi, true
	}
	return -1, false
}

// order returns the indexes of the other servers, best first (unknown ones keep the list order after known ones).
func (s *srvStats) order(list []Server, cur Server, net string, bucket int) []int {
	curID := srvID(cur)
	type it struct {
		i  int
		sc float64
		n  int
	}
	var items []it
	for i, p := range list {
		if srvID(p) == curID || p.Gone {
			continue
		}
		sc, n := s.score(net, bucket, srvID(p))
		items = append(items, it{i, sc, n})
	}
	// stable insertion sort: known and better first
	for a := 1; a < len(items); a++ {
		for b := a; b > 0; b-- {
			x, y := items[b-1], items[b]
			xk, yk := x.n >= minSamples, y.n >= minSamples
			if (yk && !xk) || (yk && xk && y.sc > x.sc) {
				items[b-1], items[b] = y, x
			} else {
				break
			}
		}
	}
	out := make([]int, len(items))
	for i, x := range items {
		out[i] = x.i
	}
	return out
}

func (s *srvStats) flush() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return
	}
	b, _ := json.Marshal(s)
	s.dirty = false
	s.mu.Unlock()
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func (a *App) srvStatsLoop() {
	for {
		select {
		case <-a.quit:
			a.srv.flush()
			return
		case <-time.After(5 * time.Minute):
			a.srv.flush()
		}
	}
}

// smartSwitch moves to the server that worked clearly better in this network at this time of day.
func (a *App) smartSwitch(netKey string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.st.Profiles) < 2 {
		return "", false
	}
	i, ok := a.srv.best(a.st.Profiles, a.st.Server, netKey, bucketOf(time.Now()))
	if !ok {
		return "", false
	}
	a.st.Server = a.st.Profiles[i]
	a.rev.Add(1)
	_ = saveSettings(a.dataDir, a.st)
	n := a.st.Server.Name
	if n == "" {
		n = a.st.Server.Host
	}
	return n, true
}

type srvHistCell struct {
	N  int `json:"n"`  // проверок
	OK int `json:"ok"` // % успешных, -1 если данных нет
	Ms int `json:"ms"` // средняя задержка, 0 если нет
}

type srvHistRow struct {
	Name    string         `json:"name"`
	Current bool           `json:"current"`
	B       [4]srvHistCell `json:"b"`
}

// history sums cells of all networks per server and part of the day.
func (s *srvStats) history(list []Server, cur Server) []srvHistRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(list) == 0 {
		list = []Server{cur}
	}
	rows := make([]srvHistRow, 0, len(list))
	for _, p := range list {
		id := srvID(p)
		r := srvHistRow{Name: p.Name, Current: id == srvID(cur)}
		if r.Name == "" {
			r.Name = p.Host
		}
		for b := 0; b < 4; b++ {
			suf := "/" + itoa(b) + "/" + id
			ok, fail := 0, 0
			var ms int64
			for k, c := range s.M {
				if len(k) > len(suf) && k[len(k)-len(suf):] == suf {
					ok += c.OK
					fail += c.Fail
					ms += c.Ms
				}
			}
			cell := srvHistCell{N: ok + fail, OK: -1}
			if cell.N > 0 {
				cell.OK = ok * 100 / cell.N
			}
			if ok > 0 {
				cell.Ms = int(ms / int64(ok))
			}
			r.B[b] = cell
		}
		rows = append(rows, r)
	}
	return rows
}

func (a *App) handleSrvStats(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	list := append([]Server(nil), a.st.Profiles...)
	cur := a.st.Server
	a.mu.Unlock()
	writeJSON(w, 200, map[string]any{"rows": a.srv.history(list, cur), "bucket": bucketOf(time.Now())})
}
