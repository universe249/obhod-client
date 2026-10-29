package main

import (
	"encoding/binary"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Счётчик рекламы. Ядро отправляет DNS-запросы к рекламным адресам не «в никуда», а сюда — в маленький DNS-сервер
// внутри программы. Он отвечает «такого адреса нет» (как и раньше) и заодно считает: сколько заблокировано сегодня,
// всего и какие адреса чаще всего. Если сервер не поднялся, ядро отвечает само (без счётчика).

const adDNSPreferredPort = 19053

var adDNSPort atomic.Int32 // 0 — встроенного сервера нет, ядро блокирует само

type adStatsFile struct {
	Day   string         `json:"day"`
	Today int            `json:"today"`
	Total int64          `json:"total"`
	Top   map[string]int `json:"top"` // за сегодня
}

type adCounter struct {
	mu     sync.Mutex
	path   string
	s      adStatsFile
	recent map[string]time.Time // одно и то же имя (запросы A и AAAA, повторы) считаем один раз за 3 секунды
	dirty  bool
}

func newAdCounter(dataDir string) *adCounter {
	c := &adCounter{path: filepath.Join(dataDir, "adstats.json"), recent: map[string]time.Time{}}
	if b, err := os.ReadFile(c.path); err == nil {
		_ = json.Unmarshal(b, &c.s)
	}
	if c.s.Top == nil {
		c.s.Top = map[string]int{}
	}
	return c
}

func (c *adCounter) add(name string, now time.Time) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.recent[name]; ok && now.Sub(t) < 3*time.Second {
		return
	}
	c.recent[name] = now
	if len(c.recent) > 2000 {
		for k, t := range c.recent {
			if now.Sub(t) > 3*time.Second {
				delete(c.recent, k)
			}
		}
	}
	day := now.Format("2006-01-02")
	if c.s.Day != day {
		c.s.Day, c.s.Today, c.s.Top = day, 0, map[string]int{}
	}
	c.s.Today++
	c.s.Total++
	if len(c.s.Top) < 3000 || c.s.Top[siteOf(name)] > 0 {
		c.s.Top[siteOf(name)]++
	}
	c.dirty = true
}

// siteOf: рекламный адрес → «сайт» для топа (ads.example.co.uk → example.co.uk, an.yandex.ru → yandex.ru).
func siteOf(name string) string {
	p := strings.Split(name, ".")
	if len(p) <= 2 {
		return name
	}
	n := 2
	if l := p[len(p)-2]; len(l) <= 3 && len(p) >= 3 && (l == "co" || l == "com" || l == "net" || l == "org") {
		n = 3
	}
	return strings.Join(p[len(p)-n:], ".")
}

type adSite struct {
	Site string `json:"site"`
	N    int    `json:"n"`
}

func (c *adCounter) view(now time.Time, top int) (today int, total int64, sites []adSite) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.s.Day != now.Format("2006-01-02") {
		return 0, c.s.Total, nil
	}
	for k, v := range c.s.Top {
		sites = append(sites, adSite{k, v})
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].N != sites[j].N {
			return sites[i].N > sites[j].N
		}
		return sites[i].Site < sites[j].Site
	})
	if len(sites) > top {
		sites = sites[:top]
	}
	return c.s.Today, c.s.Total, sites
}

func (c *adCounter) flush() {
	c.mu.Lock()
	if !c.dirty {
		c.mu.Unlock()
		return
	}
	b, _ := json.Marshal(c.s)
	c.dirty = false
	c.mu.Unlock()
	_ = os.WriteFile(c.path, b, 0o600)
}

// nxdomainReply: ответ «такого имени нет» на DNS-запрос q и имя из вопроса. ok=false — это не DNS-запрос.
func nxdomainReply(q []byte) (resp []byte, name string, ok bool) {
	if len(q) < 12 || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil, "", false
	}
	i := 12
	var labels []string
	for {
		if i >= len(q) {
			return nil, "", false
		}
		l := int(q[i])
		if l == 0 {
			i++
			break
		}
		if l > 63 || i+1+l > len(q) {
			return nil, "", false
		}
		labels = append(labels, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	if i+4 > len(q) {
		return nil, "", false
	}
	end := i + 4
	resp = make([]byte, end)
	copy(resp, q[:end])
	resp[2] = 0x80 | (q[2] & 0x79) // QR=1, тот же код операции, RD как в запросе
	resp[3] = 0x80 | 3             // RA=1, RCODE=3 (NXDOMAIN)
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp, strings.Join(labels, "."), true
}

// startAdDNS поднимает DNS-сервер счётчика на 127.0.0.1 (предпочтительно на постоянном порту).
func (a *App) startAdDNS() {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:"+itoa(adDNSPreferredPort))
	if err != nil {
		pc, err = net.ListenPacket("udp4", "127.0.0.1:0")
	}
	if err != nil {
		log.Printf("счётчик рекламы: %v", err)
		return
	}
	adDNSPort.Store(int32(pc.LocalAddr().(*net.UDPAddr).Port))
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				select {
				case <-a.quit:
					return
				default:
				}
				continue
			}
			resp, name, ok := nxdomainReply(buf[:n])
			if !ok {
				continue
			}
			a.ads.add(name, time.Now())
			_, _ = pc.WriteTo(resp, from)
		}
	}()
	go func() {
		for {
			select {
			case <-a.quit:
				a.ads.flush()
				_ = pc.Close()
				return
			case <-time.After(2 * time.Minute):
				a.ads.flush()
			}
		}
	}()
}

// GET /api/adstats — сколько рекламы заблокировано сегодня и всего, и топ сайтов за сегодня.
func (a *App) handleAdStats(w http.ResponseWriter, r *http.Request) {
	today, total, sites := a.ads.view(time.Now(), 5)
	writeJSON(w, 200, map[string]any{"on": a.settings().AdBlock, "today": today, "total": total, "top": sites, "counting": adDNSPort.Load() > 0})
}
