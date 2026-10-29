package main

import (
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Smart block hints: if direct connections to a site keep timing out or resetting, offer to route it via the server.

var (
	hintFailRe = regexp.MustCompile(`ERROR .*open connection to ([^\s:]+):\d+ using outbound/direct\S*: .*(i/o timeout|connection reset|connection refused|forcibly closed|EOF)`)
	hintDNSRe  = regexp.MustCompile(`dns: exchanged A (\S+?)\.? \d+ IN A (\d+\.\d+\.\d+\.\d+)`)
)

const hintMinFails = 3

type Hint struct {
	Name  string `json:"name"` // domain (or IP)
	Fails int    `json:"fails"`
	IsIP  bool   `json:"isIp"`
}

// parseHints extracts blocked-looking targets from a box.log tail.
func parseHints(log string, st Settings) []Hint {
	ip2host := map[string]string{}
	for _, m := range hintDNSRe.FindAllStringSubmatch(log, -1) {
		ip2host[m[2]] = m[1]
	}
	counts := map[string]int{}
	for _, l := range strings.Split(log, "\n") {
		m := hintFailRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		t := m[1]
		if net.ParseIP(t) != nil {
			if h, ok := ip2host[t]; ok {
				t = siteKey(h)
			}
		} else {
			t = siteKey(t)
		}
		counts[t]++
	}
	ignored := map[string]bool{}
	for _, s := range st.IgnoredHints {
		ignored[s] = true
	}
	var out []Hint
	for name, n := range counts {
		if n < hintMinFails || ignored[name] || hintCovered(name, st) {
			continue
		}
		out = append(out, Hint{Name: name, Fails: n, IsIP: net.ParseIP(name) != nil})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Fails != out[j].Fails {
			return out[i].Fails > out[j].Fails
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

func hintCovered(name string, st Settings) bool {
	for _, d := range st.CustomDomains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	for _, c := range st.CustomCIDRs {
		if c == name || c == name+"/32" {
			return true
		}
	}
	return false
}

type hintCache struct {
	mu   sync.Mutex
	at   time.Time
	list []Hint
}

func (a *App) currentHints() []Hint {
	if !a.core.Running() {
		return []Hint{}
	}
	a.hints.mu.Lock()
	defer a.hints.mu.Unlock()
	if time.Since(a.hints.at) < 30*time.Second && a.hints.list != nil {
		return a.hints.list
	}
	text := stripANSI(tailFile(filepath.Join(a.dataDir, "box.log"), 200000))
	a.hints.list = parseHints(text, a.settings())
	if a.hints.list == nil {
		a.hints.list = []Hint{}
	}
	a.hints.at = time.Now()
	return a.hints.list
}

func (a *App) handleHints(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string `json:"action"` // accept | ignore
		Name   string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	name := strings.ToLower(strings.TrimSpace(in.Name))
	if name == "" {
		fail(w, 400, "пустое имя")
		return
	}
	a.mu.Lock()
	switch in.Action {
	case "accept":
		if ip := net.ParseIP(name); ip != nil {
			a.st.CustomCIDRs = addUnique(a.st.CustomCIDRs, name)
		} else {
			a.st.CustomDomains = addUnique(a.st.CustomDomains, name)
		}
	case "ignore":
		a.st.IgnoredHints = addUnique(a.st.IgnoredHints, name)
	default:
		a.mu.Unlock()
		fail(w, 400, "неизвестное действие")
		return
	}
	a.rev.Add(1)
	st := a.st
	a.mu.Unlock()
	if err := saveSettings(a.dataDir, st); err != nil {
		fail(w, 500, err.Error())
		return
	}
	a.hints.mu.Lock()
	a.hints.list = nil
	a.hints.mu.Unlock()
	if in.Action == "accept" && a.core.Running() {
		if err := a.restartCore(); err != nil {
			fail(w, 500, err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func addUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
