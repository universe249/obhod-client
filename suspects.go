package main

import (
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// «Умный режим 2.0»: программа сама замечает сайты, которые не открываются напрямую.
//
// Раз в 5 секунд программа и так берёт у ядра список соединений (для статистики). Признак блокировки по содержимому:
// соединение пошло напрямую на 443, программа отправила запрос (ClientHello), а в ответ не пришло ни байта —
// соединение висит или закрылось пустым. Если так уже 3 раза за 15 минут и за это время с сайтом не было ни одного
// нормального соединения, сайт попадает в подсказки: «не открывается напрямую — пустить через сервер?».

const (
	suspectWindow   = 15 * time.Minute
	suspectFailures = 3
	stallAfter      = 8 * time.Second // столько ждём первого байта ответа
	okBytes         = 20 << 10        // столько получено — значит, сайт напрямую работает
)

type connObs struct {
	ID      string
	Host    string // имя сайта (из sniff); пусто — соединение по голому IP, его не оцениваем
	Port    string
	Direct  bool
	Up      int64
	Down    int64
	Started time.Time
}

type suspectTracker struct {
	mu      sync.Mutex
	live    map[string]connObs // соединения, ещё без ответа: id → последнее состояние
	counted map[string]bool    // это соединение уже записано как неудача
	fails   map[string][]time.Time
	oks     map[string]time.Time
	told    map[string]time.Time // когда уже сообщали (не чаще раза в сутки)
}

func newSuspectTracker() *suspectTracker {
	return &suspectTracker{live: map[string]connObs{}, counted: map[string]bool{}, fails: map[string][]time.Time{}, oks: map[string]time.Time{}, told: map[string]time.Time{}}
}

func suspectEligible(c connObs) bool {
	return c.Direct && c.Port == "443" && c.Host != "" && net.ParseIP(c.Host) == nil && strings.Contains(c.Host, ".")
}

// observe получает текущий список соединений ядра. Возвращает сайты, которые только что стали подозрительными.
func (t *suspectTracker) observe(now time.Time, conns []connObs) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	seen := map[string]bool{}
	var fresh []string
	fail := func(c connObs) {
		if t.counted[c.ID] {
			return
		}
		t.counted[c.ID] = true
		site := siteOf(c.Host)
		t.fails[site] = append(t.fails[site], now)
		if t.isSuspect(site, now) && now.Sub(t.told[site]) > 24*time.Hour {
			t.told[site] = now
			fresh = append(fresh, site)
		}
	}
	for _, c := range conns {
		if !suspectEligible(c) {
			continue
		}
		seen[c.ID] = true
		if c.Down >= okBytes {
			t.oks[siteOf(c.Host)] = now
			delete(t.live, c.ID)
			continue
		}
		if c.Down == 0 && c.Up >= 100 {
			t.live[c.ID] = c
			if !c.Started.IsZero() && now.Sub(c.Started) >= stallAfter {
				fail(c) // висит без ответа
			}
		} else {
			delete(t.live, c.ID)
		}
	}
	// закрылись, так ничего и не получив (сброс соединения)
	for id, c := range t.live {
		if !seen[id] {
			delete(t.live, id)
			if c.Down == 0 && c.Up >= 100 {
				fail(c)
			}
		}
	}
	// чистка старого
	for site, list := range t.fails {
		k := 0
		for _, x := range list {
			if now.Sub(x) <= suspectWindow {
				list[k] = x
				k++
			}
		}
		if k == 0 {
			delete(t.fails, site)
		} else {
			t.fails[site] = list[:k]
		}
	}
	if len(t.counted) > 5000 {
		t.counted = map[string]bool{}
	}
	return fresh
}

func (t *suspectTracker) isSuspect(site string, now time.Time) bool {
	n := 0
	for _, x := range t.fails[site] {
		if now.Sub(x) <= suspectWindow {
			n++
		}
	}
	return n >= suspectFailures && now.Sub(t.oks[site]) > suspectWindow
}

type suspectSite struct {
	Site  string `json:"site"`
	Fails int    `json:"fails"`
}

func (t *suspectTracker) list(now time.Time, skip func(string) bool) []suspectSite {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []suspectSite
	for site, list := range t.fails {
		if t.isSuspect(site, now) && !skip(site) {
			out = append(out, suspectSite{site, len(list)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fails > out[j].Fails })
	return out
}

func (t *suspectTracker) forget(site string) {
	t.mu.Lock()
	delete(t.fails, site)
	t.mu.Unlock()
}

// suspectSkip: сайты, о которых подсказывать не нужно — уже идут через сервер, уже «напрямую» по выбору, скрыты.
func suspectSkip(st Settings) func(string) bool {
	has := func(list []string, site string) bool {
		for _, d := range list {
			d = normDomain(d)
			if d == site || strings.HasSuffix(site, "."+d) || strings.HasSuffix(d, "."+site) {
				return true
			}
		}
		return false
	}
	return func(site string) bool {
		return has(st.CustomDomains, site) || has(st.DirectDomains, site) || has(st.SuggestIgnore, site)
	}
}

// GET /api/suggest — подсказки; POST {"site": "...", "action": "proxy"|"ignore"} — пустить через сервер или скрыть.
func (a *App) handleSuggest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		st := a.settings()
		list := []suspectSite{}
		if st.Suggest && !effectiveGlobal(st, time.Now()) {
			if l := a.suspects.list(time.Now(), suspectSkip(st)); l != nil {
				list = l
			}
		}
		writeJSON(w, 200, map[string]any{"on": st.Suggest, "sites": list})
		return
	}
	var in struct {
		Site   string `json:"site"`
		Action string `json:"action"`
		On     *bool  `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	if in.On != nil { // включить или выключить подсказки
		a.mu.Lock()
		a.st.Suggest = *in.On
		st := a.st
		a.mu.Unlock()
		_ = saveSettings(a.dataDir, st)
		writeJSON(w, 200, map[string]any{"ok": true, "on": st.Suggest})
		return
	}
	site := normDomain(in.Site)
	if site == "" {
		fail(w, 400, "пустой адрес")
		return
	}
	a.mu.Lock()
	switch in.Action {
	case "proxy":
		a.st.CustomDomains = uniq(append(a.st.CustomDomains, site))
		a.st.DirectDomains = removeStr(a.st.DirectDomains, site)
	case "ignore":
		a.st.SuggestIgnore = uniq(append(a.st.SuggestIgnore, site))
	default:
		a.mu.Unlock()
		fail(w, 400, "неизвестное действие")
		return
	}
	a.rev.Add(1)
	st := a.st
	a.mu.Unlock()
	a.suspects.forget(site)
	if err := saveSettings(a.dataDir, st); err != nil {
		fail(w, 500, err.Error())
		return
	}
	if in.Action == "proxy" && a.core.Running() {
		if err := a.restartCore(); err != nil {
			fail(w, 500, "Сайт добавлен, но туннель не перезапустился: "+err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
