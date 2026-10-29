package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Server addresses are resolved once, before the tunnel starts, and written into the config as IPs.
// Resolving the server's own domain inside sing-box competes with the first burst of traffic after a
// start and sometimes times out ("lookup <host>: context deadline exceeded"); an IP needs no lookup.
// The domain still goes into TLS server_name / WebSocket Host (outboundFor sets them explicitly).

var (
	pinMu sync.RWMutex
	pins  = map[string]string{} // host -> IPv4
)

type pinCache map[string]struct {
	IP string `json:"ip"`
	At int64  `json:"at"`
}

func pinnedIP(host string) string {
	pinMu.RLock()
	defer pinMu.RUnlock()
	return pins[host]
}

func setPins(p map[string]string) {
	pinMu.Lock()
	pins = p
	pinMu.Unlock()
}

// pinServers resolves every server host of the settings. A failed lookup falls back to the last
// address seen (kept for 30 days); with no cache the domain stays as is.
func pinServers(st Settings, dataDir string) {
	cachePath := filepath.Join(dataDir, "hostcache.json")
	cache := pinCache{}
	if b, err := os.ReadFile(cachePath); err == nil {
		_ = json.Unmarshal(b, &cache)
	}
	out := map[string]string{}
	changed := false
	for _, sv := range allServers(st) {
		h := sv.Host
		if h == "" || net.ParseIP(h) != nil || needsXray(sv) {
			continue
		}
		if _, done := out[h]; done {
			continue
		}
		if ip := lookupV4(h, 4*time.Second); ip != "" {
			out[h] = ip
			if cache[h].IP != ip {
				cache[h] = struct {
					IP string `json:"ip"`
					At int64  `json:"at"`
				}{ip, time.Now().Unix()}
				changed = true
			}
			continue
		}
		if c, ok := cache[h]; ok && c.IP != "" && time.Since(time.Unix(c.At, 0)) < 30*24*time.Hour {
			out[h] = c.IP
		}
	}
	setPins(out)
	if changed {
		if b, err := json.Marshal(cache); err == nil {
			_ = os.WriteFile(cachePath, b, 0o600)
		}
	}
}

func lookupV4(host string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

// pinOutbound swaps the server host for its pinned IP.
func pinOutbound(o m) {
	if o == nil {
		return
	}
	h, _ := o["server"].(string)
	if h == "" {
		return
	}
	if ip := pinnedIP(h); ip != "" {
		o["server"] = ip
	}
}
