package main

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Журнал связи: раз в минуту программа сама проверяет каждый путь к текущему серверу (напрямую и через ретрансляторы)
// и обычный интернет — TLS-рукопожатием мимо туннеля, то есть настоящим обменом данными, а не открытием порта.
// Сутки хранятся в linklog.json и попадают в отчёт администратору: по ним видно, что и когда резал провайдер.

type linkPoint struct {
	T int64          `json:"t"`
	R map[string]int `json:"r"` // путь → мс, -1 — нет ответа
}

type linkLog struct {
	mu     sync.Mutex
	points []linkPoint
}

const linkKeep = 24 * 60

func (l *linkLog) add(p linkPoint) {
	l.mu.Lock()
	l.points = append(l.points, p)
	if len(l.points) > linkKeep {
		l.points = append([]linkPoint(nil), l.points[len(l.points)-linkKeep:]...)
	}
	l.mu.Unlock()
}

func (l *linkLog) snapshot() []linkPoint {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]linkPoint(nil), l.points...)
}

func (l *linkLog) load(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var pts []linkPoint
	if json.Unmarshal(b, &pts) == nil {
		cut := time.Now().Add(-24 * time.Hour).Unix()
		for _, p := range pts {
			if p.T >= cut {
				l.points = append(l.points, p)
			}
		}
	}
}

func (l *linkLog) save(path string) {
	b, err := json.Marshal(l.snapshot())
	if err == nil {
		_ = os.WriteFile(path, b, 0o600)
	}
}

type linkTarget struct {
	Label, Host, SNI string
	Port             int
}

// linkTargets: текущий сервер и его пути; UDP-входы (Hysteria2) так не проверить — их нет в журнале.
func linkTargets(st Settings) []linkTarget {
	var out []linkTarget
	add := func(s Server) {
		if s.Host == "" || s.Type == "hysteria2" {
			return
		}
		label := "напрямую"
		if v := splitVia(s.Name); v != "" {
			label = "через " + v
		} else if s.Port != st.Server.Port {
			label = "порт " + strconv.Itoa(s.Port)
		}
		sni := s.SNI
		if sni == "" {
			sni = s.Host
		}
		out = append(out, linkTarget{label, s.Host, sni, s.Port})
	}
	add(st.Server)
	if serviceOK(st) {
		for _, p := range pathsFor(st) {
			add(p)
		}
	}
	return append(out, linkTarget{"интернет", "ya.ru", "ya.ru", 443})
}

func tlsProbe(t linkTarget) int {
	dialers := append(physicalDialers(5*time.Second), &net.Dialer{Timeout: 5 * time.Second})
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	for _, d := range dialers {
		t0 := time.Now()
		raw, err := d.Dial("tcp", addr)
		if err != nil {
			continue
		}
		c := tls.Client(raw, &tls.Config{ServerName: t.SNI, InsecureSkipVerify: true}) //nolint:gosec // проверяем доступность, а не подлинность
		_ = c.SetDeadline(time.Now().Add(7 * time.Second))
		err = c.Handshake()
		c.Close()
		if err == nil || !isTimeout(err) {
			// отказ сервера (чужое имя, Reality) — ответ пришёл, данные проходят
			return int(time.Since(t0).Milliseconds())
		}
		return -1
	}
	return -1
}

func (a *App) linkLogLoop() {
	path := filepath.Join(a.dataDir, "linklog.json")
	a.links.load(path)
	saved := time.Now()
	for {
		select {
		case <-a.quit:
			a.links.save(path)
			return
		case <-time.After(time.Minute):
		}
		targets := linkTargets(a.settings())
		res := map[string]int{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, t := range targets {
			wg.Add(1)
			go func(t linkTarget) {
				defer wg.Done()
				ms := tlsProbe(t)
				mu.Lock()
				res[t.Label] = ms
				mu.Unlock()
			}(t)
		}
		wg.Wait()
		a.links.add(linkPoint{T: time.Now().Unix(), R: res})
		if a.core.Running() {
			if rs, send := a.radar.step(res, time.Now()); send {
				go a.radarReport(rs)
			}
		}
		if time.Since(saved) > 10*time.Minute {
			a.links.save(path)
			saved = time.Now()
		}
	}
}

// GET /api/linklog — журнал связи за сутки.
func (a *App) handleLinkLog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"points": a.links.snapshot()})
}
