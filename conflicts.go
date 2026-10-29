package main

import (
	"strings"
	"sync"
	"time"
)

// Conflict is a running program that is known to interfere with a TUN tunnel.
type Conflict struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // vpn | antivirus
	Text string `json:"text"`
}

type sig struct {
	proc, name, kind, text string
}

var conflictSigs = []sig{
	{"warp-svc.exe", "Cloudflare WARP", "vpn", "Выключи WARP (Disconnect) — два туннеля подряд ломают сеть."},
	{"cloudflare warp.exe", "Cloudflare WARP", "vpn", "Выключи WARP (Disconnect) — два туннеля подряд ломают сеть."},
	{"openvpn.exe", "OpenVPN", "vpn", "Отключи OpenVPN на время работы туннеля."},
	{"openvpn-gui.exe", "OpenVPN", "vpn", "Отключи OpenVPN на время работы туннеля."},
	{"wireguard.exe", "WireGuard", "vpn", "Отключи туннель WireGuard."},
	{"v2rayn.exe", "v2rayN", "vpn", "Закрой v2rayN — он тоже занимает сеть и порты."},
	{"nekoray.exe", "NekoRay", "vpn", "Закрой NekoRay."},
	{"nekobox.exe", "NekoBox", "vpn", "Закрой NekoBox."},
	{"hiddify.exe", "Hiddify", "vpn", "Закрой Hiddify."},
	{"clash-verge.exe", "Clash Verge", "vpn", "Закрой Clash Verge."},
	{"clash.exe", "Clash", "vpn", "Закрой Clash."},
	{"mihomo.exe", "Mihomo/Clash", "vpn", "Закрой Mihomo."},
	{"nordvpn-service.exe", "NordVPN", "vpn", "Отключи NordVPN."},
	{"expressvpnd.exe", "ExpressVPN", "vpn", "Отключи ExpressVPN."},
	{"protonvpn.exe", "Proton VPN", "vpn", "Отключи Proton VPN."},
	{"windscribe.exe", "Windscribe", "vpn", "Отключи Windscribe."},
	{"outline.exe", "Outline", "vpn", "Отключи Outline."},
	{"amneziavpn.exe", "AmneziaVPN", "vpn", "Отключи AmneziaVPN."},
	{"avp.exe", "Kaspersky", "antivirus", "Если туннель не поднимается — добавь папку программы в исключения Kaspersky и разреши её в сетевом экране."},
	{"ekrn.exe", "ESET", "antivirus", "Если туннель не поднимается — добавь папку программы в исключения ESET."},
	{"dwservice.exe", "Dr.Web", "antivirus", "Если туннель не поднимается — добавь папку программы в исключения Dr.Web."},
	{"avastsvc.exe", "Avast", "antivirus", "Если туннель не поднимается — добавь папку программы в исключения Avast."},
	{"avgsvc.exe", "AVG", "antivirus", "Если туннель не поднимается — добавь папку программы в исключения AVG."},
	{"nortonsecurity.exe", "Norton", "antivirus", "Если туннель не поднимается — добавь папку программы в исключения Norton."},
	{"bdservicehost.exe", "Bitdefender", "antivirus", "Если туннель не поднимается — добавь папку программы в исключения Bitdefender."},
}

func detectConflicts(procs []string) []Conflict {
	have := map[string]bool{}
	for _, p := range procs {
		have[strings.ToLower(p)] = true
	}
	var res []Conflict
	seen := map[string]bool{}
	for _, s := range conflictSigs {
		if have[s.proc] && !seen[s.name] {
			seen[s.name] = true
			res = append(res, Conflict{Name: s.name, Kind: s.kind, Text: s.text})
		}
	}
	return res
}

type conflictCache struct {
	mu   sync.Mutex
	at   time.Time
	list []Conflict
}

// get refreshes at most every 30 s (listing processes is not free).
func (c *conflictCache) get() []Conflict {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) > 30*time.Second {
		c.list = detectConflicts(listProcesses())
		c.at = time.Now()
	}
	return c.list
}
