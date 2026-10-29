package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Запасной IP сервера. Пока домен сервера определяется, запоминаем его адрес. Если потом DNS (чаще всего на роутере)
// перестаёт отвечать, туннель собирается по запомненному IP, а имя для проверки сертификата остаётся прежним.

type hostIPCache struct {
	mu       sync.Mutex
	known    map[string]string // домен -> последний рабочий IP
	override map[string]string // домен -> IP, который сейчас подставляется
}

var hostIPs = &hostIPCache{known: map[string]string{}, override: map[string]string{}}

// lookupHostFn подменяется в тестах.
var lookupHostFn = func(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, host)
}

func hostIPsPath(dir string) string { return filepath.Join(dir, "hostips.json") }

func (c *hostIPCache) load(dir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, err := os.ReadFile(hostIPsPath(dir)); err == nil {
		m := map[string]string{}
		if json.Unmarshal(b, &m) == nil {
			c.known = m
		}
	}
}

func (c *hostIPCache) save(dir string) {
	c.mu.Lock()
	b, _ := json.Marshal(c.known)
	c.mu.Unlock()
	_ = os.WriteFile(hostIPsPath(dir), b, 0o600)
}

func domainHosts(st Settings) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append([]Server{st.Server}, st.Profiles...) {
		if s.Host == "" || net.ParseIP(s.Host) != nil || seen[s.Host] {
			continue
		}
		seen[s.Host] = true
		out = append(out, s.Host)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

func pickIP(ips []string) string {
	for _, s := range ips { // IPv4 надёжнее
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			return s
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	return ""
}

// refresh: перед запуском туннеля. Домен определился — запоминаем IP и снимаем подмену. Не определился, а IP известен — подменяем.
func (c *hostIPCache) refresh(dir string, st Settings) {
	changed := false
	for _, h := range domainHosts(st) {
		ips, err := lookupHostFn(h)
		ip := pickIP(ips)
		c.mu.Lock()
		if err == nil && ip != "" {
			delete(c.override, h)
			if c.known[h] != ip {
				c.known[h] = ip
				changed = true
			}
		} else if old := c.known[h]; old != "" {
			c.override[h] = old
			log.Printf("dns: %s не определяется, использую сохранённый адрес", h)
		}
		c.mu.Unlock()
	}
	if changed {
		c.save(dir)
	}
}

// overrideActive: подставляется ли сейчас сохранённый IP для этого сервера.
func (c *hostIPCache) overrideActive(host string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ip, ok := c.override[host]
	return ip, ok
}

// applyHostOverride меняет адрес на сохранённый IP, сохраняя имена для TLS и заголовка Host.
func applyHostOverride(s Server) Server {
	ip, ok := hostIPs.overrideActive(s.Host)
	if !ok {
		return s
	}
	if s.SNI == "" {
		s.SNI = s.Host
	}
	if s.WSHost == "" {
		s.WSHost = s.Host
	}
	s.Host = ip
	return s
}
