package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"
)

// The auto-tuner measures how each saved server (and each "way" to reach it: as saved, with TLS
// fragmentation flipped, with multiplexing flipped) behaves on the current network, and keeps the best.
// Everything runs through the local test proxy, so the tunnel does not have to be restarted to measure.

type tuneCand struct {
	Server int     `json:"server"` // index in allServers
	Kind   string  `json:"kind"`   // "" | f | m
	Name   string  `json:"name"`
	Way    string  `json:"way"`
	User   string  `json:"-"`
	Ok     int     `json:"ok"`    // successful probes out of tuneProbes
	Ms     int     `json:"ms"`    // median time of the successful ones
	Mbit   float64 `json:"mbit"`  // download speed, 0 when not measured
	Score  float64 `json:"score"` // higher is better, 0 = unusable
	Active bool    `json:"active"`
	Err    string  `json:"err,omitempty"`
}

type tuneState struct {
	mu       sync.Mutex
	Running  bool
	Phase    string
	Done     int
	Total    int
	Cands    []tuneCand
	Winner   int // index in Cands, -1 when none is better than the current one
	Started  time.Time
	Finished time.Time
	cancel   context.CancelFunc
	lastAuto time.Time
}

const tuneProbes = 3

// probe URLs: three different hosts, a fresh connection each time (the slow part on a throttled link)
var tuneURLs = []string{
	"https://www.gstatic.com/generate_204",
	"https://www.cloudflare.com/cdn-cgi/trace",
	"https://www.youtube.com/generate_204",
}

func wayLabel(kind string, sv Server, frag bool) string {
	switch kind {
	case kindFrag:
		if frag { // the variant flips the current state
			return "с фрагментацией TLS"
		}
		return "без фрагментации TLS"
	case kindMux:
		if sv.Mux {
			return "без мультиплексирования"
		}
		return "с мультиплексированием"
	case kindFP1, kindFP2:
		for k, f := range altFingerprints(sv) {
			if fpKinds()[k] == kind {
				return "отпечаток " + f
			}
		}
	}
	return "как сохранён"
}

// tuneCandidates lists everything the running config can test.
func tuneCandidates(st Settings) []tuneCand {
	servers := allServers(st)
	have := map[string]bool{}
	for _, e := range serverExits(st, servers) {
		have[e.User] = true
	}
	var out []tuneCand
	for i, sv := range servers {
		if needsXray(sv) {
			continue
		}
		frag := fragFor(st, sv)
		base := probeUserFor(i)
		if i == 0 && !have[base] {
			base = probeUserProxy
		}
		if !have[base] && base != probeUserProxy {
			continue
		}
		name := serverKey(sv)
		out = append(out, tuneCand{Server: i, Kind: kindBase, Name: name, Way: wayLabel(kindBase, sv, frag), User: base, Active: i == 0})
		if have[exitUser(i, kindFrag)] {
			out = append(out, tuneCand{Server: i, Kind: kindFrag, Name: name, Way: wayLabel(kindFrag, sv, !frag), User: exitUser(i, kindFrag)})
		}
		if have[exitUser(i, kindMux)] {
			out = append(out, tuneCand{Server: i, Kind: kindMux, Name: name, Way: wayLabel(kindMux, sv, frag), User: exitUser(i, kindMux)})
		}
		for _, k := range fpKinds() {
			if have[exitUser(i, k)] {
				out = append(out, tuneCand{Server: i, Kind: k, Name: name, Way: wayLabel(k, sv, frag), User: exitUser(i, k)})
			}
		}
	}
	return out
}

func median(v []int) int {
	if len(v) == 0 {
		return 0
	}
	sort.Ints(v)
	return v[len(v)/2]
}

// stage 1: three quick requests, each over a new connection.
func probeConnect(ctx context.Context, st Settings, c *tuneCand) {
	cl := probeClient(st, c.User, 8*time.Second)
	var ms []int
	for _, u := range tuneURLs[:tuneProbes] {
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		t0 := time.Now()
		resp, err := cl.Do(req)
		if err != nil {
			c.Err = shortErr(err)
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		ms = append(ms, int(time.Since(t0).Milliseconds()))
	}
	c.Ok = len(ms)
	c.Ms = median(ms)
	if c.Ok > 0 {
		c.Err = ""
	}
}

// stage 2: download speed; a stalled stream shows up as a tiny number.
func probeSpeed(ctx context.Context, st Settings, c *tuneCand) {
	cctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()
	cl := probeClient(st, c.User, 12*time.Second)
	u := (&url.URL{Scheme: "https", Host: "speed.cloudflare.com", Path: "/__down", RawQuery: "bytes=3000000"}).String()
	req, _ := http.NewRequestWithContext(cctx, "GET", u, nil)
	resp, err := cl.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	t0 := time.Now()
	n, _ := io.Copy(io.Discard, resp.Body)
	d := time.Since(t0).Seconds()
	if d < 0.05 {
		d = 0.05
	}
	if n >= 50_000 {
		c.Mbit = float64(n) * 8 / d / 1e6
	}
}

func scoreOf(c tuneCand) float64 {
	if c.Ok < 2 {
		return 0
	}
	mbit := c.Mbit
	if mbit == 0 {
		mbit = 0.5 // reachable but not measured: ranks below anything measured fast
	}
	return mbit / (1 + float64(c.Ms)/1000)
}

// pickWinner returns the index of the best candidate, or -1 when the active one is good enough:
// a change has to win by a clear margin so the choice does not flip-flop.
func pickWinner(cs []tuneCand) int {
	cur, best := -1, -1
	for i, c := range cs {
		if c.Active && c.Kind == kindBase {
			cur = i
		}
		if c.Score > 0 && (best < 0 || c.Score > cs[best].Score) {
			best = i
		}
	}
	if best < 0 || best == cur {
		return -1
	}
	if cur >= 0 && cs[cur].Score > 0 && cs[best].Score < cs[cur].Score*1.25 {
		return -1
	}
	return best
}

// bestIndex is the top scorer regardless of margin (-1 when nothing works).
func bestIndex(cs []tuneCand) int {
	best := -1
	for i, c := range cs {
		if c.Score > 0 && (best < 0 || c.Score > cs[best].Score) {
			best = i
		}
	}
	return best
}

func (t *tuneState) set(f func()) {
	t.mu.Lock()
	f()
	t.mu.Unlock()
}

// run measures everything; blocks until done. The caller decides what to do with the winner.
func (a *App) runTune(ctx context.Context) {
	st := a.settings()
	cands := tuneCandidates(st)
	t := &a.tune
	t.set(func() {
		t.Running, t.Phase, t.Done, t.Total = true, "Проверяю соединения", 0, len(cands)
		t.Cands, t.Winner, t.Started, t.Finished = cands, -1, time.Now(), time.Time{}
	})
	defer t.set(func() { t.Running, t.Finished, t.Phase = false, time.Now(), "Готово" })

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i := range cands {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			c := cands[i]
			probeConnect(ctx, st, &c)
			t.set(func() { t.Cands[i] = c; t.Done++ })
		}(i)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	// stage 2: speed of the most promising ones, one at a time
	t.mu.Lock()
	order := make([]int, 0, len(t.Cands))
	for i, c := range t.Cands {
		if c.Ok >= 2 {
			order = append(order, i)
		}
	}
	sort.SliceStable(order, func(x, y int) bool {
		a, b := t.Cands[order[x]], t.Cands[order[y]]
		if a.Ok != b.Ok {
			return a.Ok > b.Ok
		}
		return a.Ms < b.Ms
	})
	if len(order) > 4 {
		order = order[:4]
	}
	t.Phase, t.Done, t.Total = "Измеряю скорость", 0, len(order)
	t.mu.Unlock()
	for _, i := range order {
		if ctx.Err() != nil {
			return
		}
		t.mu.Lock()
		c := t.Cands[i]
		t.mu.Unlock()
		probeSpeed(ctx, st, &c)
		t.set(func() { t.Cands[i] = c; t.Done++ })
	}
	t.set(func() {
		for i := range t.Cands {
			t.Cands[i].Score = scoreOf(t.Cands[i])
		}
		t.Winner = pickWinner(t.Cands)
	})
}

// applyCand makes a candidate the active way to connect. The caller restarts the tunnel.
func (a *App) applyCand(c tuneCand) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	servers := allServers(a.st)
	if c.Server < 0 || c.Server >= len(servers) {
		return ""
	}
	sv := servers[c.Server]
	switch c.Kind {
	case kindFrag:
		if fragFor(a.st, sv) {
			sv.Frag = "off"
		} else {
			sv.Frag = "on"
		}
	case kindMux:
		sv.Mux = !sv.Mux
	case kindFP1, kindFP2:
		for k, f := range altFingerprints(sv) {
			if fpKinds()[k] == c.Kind {
				sv.Fingerprint = f
			}
		}
	}
	// keep the saved copy in step so the choice survives switching servers
	for i := range a.st.Profiles {
		if sameServer(a.st.Profiles[i], sv) {
			a.st.Profiles[i].Frag, a.st.Profiles[i].Mux, a.st.Profiles[i].Fingerprint = sv.Frag, sv.Mux, sv.Fingerprint
		}
	}
	a.st.Server = sv
	a.rev.Add(1)
	_ = saveSettings(a.dataDir, a.st)
	return serverKey(sv) + " (" + c.Way + ")"
}

func (t *tuneState) snapshot() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	res := map[string]any{
		"running": t.Running, "phase": t.Phase, "done": t.Done, "total": t.Total,
		"cands": t.Cands, "winner": t.Winner, "best": bestIndex(t.Cands),
	}
	if !t.Finished.IsZero() {
		res["finished"] = t.Finished.Unix()
	}
	return res
}

// POST /api/tune {action: start | cancel | apply, index}   GET /api/tune
func (a *App) handleTune(w http.ResponseWriter, r *http.Request) {
	t := &a.tune
	if r.Method == http.MethodGet {
		writeJSON(w, 200, t.snapshot())
		return
	}
	var in struct {
		Action string `json:"action"`
		Index  int    `json:"index"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	switch in.Action {
	case "start":
		if !a.core.Running() {
			fail(w, 400, "сначала включи обход")
			return
		}
		t.mu.Lock()
		if t.Running {
			t.mu.Unlock()
			fail(w, 409, "подбор уже идёт")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		t.cancel = cancel
		t.Running = true
		t.mu.Unlock()
		go func() {
			defer cancel()
			a.runTune(ctx)
		}()
		writeJSON(w, 200, map[string]any{"ok": true})
	case "cancel":
		t.mu.Lock()
		if t.cancel != nil {
			t.cancel()
		}
		t.mu.Unlock()
		writeJSON(w, 200, map[string]any{"ok": true})
	case "apply":
		t.mu.Lock()
		i := in.Index
		if i < 0 {
			i = t.Winner
		}
		if i < 0 || i >= len(t.Cands) || t.Running {
			t.mu.Unlock()
			fail(w, 400, "нечего применять")
			return
		}
		c := t.Cands[i]
		t.mu.Unlock()
		name := a.applyCand(c)
		if name == "" {
			fail(w, 400, "сервер не найден")
			return
		}
		if a.core.Running() {
			go func() {
				a.core.Stop()
				if err := startedOK(a.core.Start(a.settings())); err != nil {
					a.notify(appName, "Не удалось перезапустить: "+err.Error())
				}
			}()
		}
		writeJSON(w, 200, map[string]any{"ok": true, "applied": name})
	default:
		fail(w, 400, "неизвестное действие")
	}
}

// autoTune is called by the watchdog when the link is bad or slow. It measures, and if something is
// clearly better it switches to it. At most once per 20 minutes. Reports whether it changed anything.
func (a *App) autoTune(reason string) (string, bool) {
	st := a.settings()
	if !st.AutoTune || !serviceOK(st) || !a.core.Running() {
		return "", false
	}
	t := &a.tune
	t.mu.Lock()
	if t.Running || time.Since(t.lastAuto) < 20*time.Minute {
		t.mu.Unlock()
		return "", false
	}
	t.lastAuto = time.Now()
	t.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	a.runTune(ctx)
	t.mu.Lock()
	w := t.Winner
	var c tuneCand
	if w >= 0 && w < len(t.Cands) {
		c = t.Cands[w]
	} else {
		w = -1
	}
	t.mu.Unlock()
	if w < 0 {
		return "", false
	}
	name := a.applyCand(c)
	if name == "" {
		return "", false
	}
	return fmt.Sprintf("%s: подобран способ «%s».", reason, name), true
}
