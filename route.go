package main

import (
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type routeHop struct {
	Label string `json:"label"`
	Ms    int    `json:"ms"` // задержка участка до этой точки; 0 — не меряется (UDP или середина пути)
	OK    bool   `json:"ok"`
	Known bool   `json:"known"` // участок проверен (иначе рисуется без числа)
}

// GET /api/route — схема маршрута для главной: ты → (ретранслятор) → сервер → интернет.
// Первый участок меряется TCP-соединением мимо TUN, весь путь — запросом через ядро по текущему выходу.
func (a *App) handleRoute(w http.ResponseWriter, r *http.Request) {
	st := a.settings()
	running, _, _, _, _ := a.core.Info()
	if !running || st.Server.Host == "" || !serviceOK(st) {
		writeJSON(w, 200, map[string]any{"on": false})
		return
	}
	cur, tag := st.Server, "proxy"
	if name := currentPath(st); name != "" {
		for i, p := range pathsFor(st) {
			if p.Name == name {
				cur, tag = p, "path-"+strconv.Itoa(i+1)
			}
		}
		if cur.Host == st.Server.Host {
			tag = "path-0"
		}
	}
	via := splitVia(cur.Name)
	hops := []routeHop{{Label: "Ты", OK: true, Known: true}}
	first := routeHop{Label: "Сервер", OK: true}
	if via != "" {
		first = routeHop{Label: via, OK: true}
	}
	if cur.Type != "hysteria2" {
		first.Known = true
		first.Ms = -1
		addr := net.JoinHostPort(cur.Host, strconv.Itoa(cur.Port))
		for _, d := range append(physicalDialers(3*time.Second), &net.Dialer{Timeout: 3 * time.Second}) {
			t0 := time.Now()
			if c, err := d.Dial("tcp", addr); err == nil {
				c.Close()
				first.Ms = int(time.Since(t0).Milliseconds())
				break
			}
		}
		first.OK = first.Ms >= 0
	}
	hops = append(hops, first)
	if via != "" {
		hops = append(hops, routeHop{Label: "Сервер", OK: first.OK})
	}
	end := routeHop{Label: "Интернет", Known: true}
	if ms, err := clashDelay(st, tag, "https://www.gstatic.com/generate_204"); err == nil && ms > 0 {
		end.Ms, end.OK = ms, true
	}
	hops = append(hops, end)
	writeJSON(w, 200, map[string]any{"on": true, "hops": hops, "server": splitBase(cur.Name)})
}

// splitVia: «vlesska (через Питер)» → «Питер»; без ретранслятора — "".
func splitVia(name string) string {
	if m := reVia.FindStringSubmatch(name); m != nil {
		return m[2]
	}
	return ""
}

func splitBase(name string) string {
	if m := reVia.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return name
}

var reVia = regexp.MustCompile(`^(.*?)\s*\(через ([^)]+)\)\s*$`)

// pathWatchLoop: при «Нескольких путях» замечает, что ядро сменило путь, и пишет это в события (видно на главной,
// уходит в анонимный отчёт — по нему видно, у каких провайдеров режут прямой путь).
func (a *App) pathWatchLoop() {
	prev := ""
	var pn pathNotifier
	for {
		select {
		case <-a.quit:
			return
		case <-time.After(5 * time.Second):
		}
		st := a.settings()
		if !a.core.Running() {
			prev = ""
			continue
		}
		cur := currentPath(st)
		if cur == "" {
			prev = ""
			continue
		}
		if prev != "" && cur != prev {
			if cur == st.Server.Name {
				a.event("ok", "Основной путь к серверу снова работает")
			} else {
				a.event("warn", "Основной путь к серверу не отвечает — связь переключилась: "+pathDesc(cur, st.Server))
			}
		}
		if msg := pn.step(cur, st.Server.Name, pathDesc(cur, st.Server), time.Now()); msg != "" && st.Notify {
			trayNotify(appName, msg)
		}
		prev = cur
	}
}

// pathNotifier решает, когда показать уведомление Windows о смене пути. Ядро может ненадолго перескочить на другой путь
// и вернуться — об этом не сообщаем: уведомление только если новый путь держится не меньше 30 секунд,
// и не чаще раза в 15 минут. О возвращении на основной путь — только если перед этим сообщили об уходе с него.
type pathNotifier struct {
	cand      string // путь, на который переключились, ждёт подтверждения
	candSince time.Time
	shown     string // о каком пути уже сообщили
	lastAt    time.Time
	away      bool // сообщили, что ушли с основного пути
}

func (p *pathNotifier) step(cur, main, desc string, now time.Time) string {
	if cur == "" {
		p.cand = ""
		return ""
	}
	if cur != p.cand {
		p.cand, p.candSince = cur, now
		return ""
	}
	if now.Sub(p.candSince) < 30*time.Second || cur == p.shown {
		return ""
	}
	if cur == main {
		p.shown = cur
		if p.away {
			p.away = false
			return "Связь снова идёт по основному пути."
		}
		return ""
	}
	if now.Sub(p.lastAt) >= 15*time.Minute {
		p.shown, p.lastAt, p.away = cur, now, true
		return "Основной путь к серверу не отвечает. Связь переключилась: " + desc + ". Всё работает дальше."
	}
	p.shown = cur // недавно уже сообщали — не повторяем
	return ""
}

// pathDesc: «через Питер», «Hysteria2», «Hysteria2 через Питер», «порт 443».
func pathDesc(name string, base Server) string {
	d := ""
	if reHy.MatchString(name) && base.Type != "hysteria2" {
		d = "Hysteria2"
	}
	if v := splitVia(name); v != "" {
		d = strings.TrimSpace(d + " через «" + v + "»")
	}
	if d == "" {
		d = "«" + name + "»"
	}
	return d
}

var reHy = regexp.MustCompile(`(?i)hysteria|hy2`)
