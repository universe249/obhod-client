package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// normDomain cleans user input such as "https://*.Example.com/path" -> "example.com".
func normDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "*.")
	s = strings.Trim(s, ".")
	return s
}

func normApp(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexAny(s, `\/`); i >= 0 {
		s = s[i+1:]
	}
	return s
}

var hopItem = regexp.MustCompile(`^(\d{1,5})(?::(\d{1,5}))?$`)

// normHop converts "20000-30000, 40000" into sing-box notation ["20000:30000", "40000"].
func normHop(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.ReplaceAll(strings.TrimSpace(p), "-", ":")
		mm := hopItem.FindStringSubmatch(p)
		if mm == nil {
			continue
		}
		a, _ := strconv.Atoi(mm[1])
		b := a
		if mm[2] != "" {
			b, _ = strconv.Atoi(mm[2])
		}
		if a < 1 || b > 65535 || a > b {
			continue
		}
		out = append(out, p)
	}
	return out
}

// normCIDR accepts "1.2.3.4" or "10.0.0.0/8" (and IPv6) and returns CIDR notation, or "".
func normCIDR(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return ""
		}
		if ip.To4() != nil {
			return s + "/32"
		}
		return s + "/128"
	}
	if _, _, err := net.ParseCIDR(s); err != nil {
		return ""
	}
	return s
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func cleanList(in []string, f func(string) string) []string {
	var out []string
	for _, v := range in {
		out = append(out, f(v))
	}
	return uniq(out)
}

const geositeURL = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-%s.srs"
const ruBlockedDomainsURL = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs"
const ruBlockedIPURL = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru-blocked.srs"

type m = map[string]any

func needsXray(s Server) bool { return s.Type == "vless" && s.Network == "xhttp" }

func outboundFor(s Server, xrayPort int) (m, error) {
	o, err := outboundBase(s, xrayPort)
	if err == nil && s.Mux && muxable(s) {
		o["multiplex"] = m{"enabled": true, "protocol": "smux", "max_connections": 4, "min_streams": 4}
	}
	return o, err
}

// muxable: protocols that can carry several streams over one connection (the server needs multiplex on too).
func muxable(s Server) bool {
	if needsXray(s) || s.Network == "ws" {
		return false
	}
	switch s.Type {
	case "vless":
		return s.Flow == "" // xtls-rprx-vision cannot be multiplexed
	case "trojan", "shadowsocks":
		return true
	}
	return false
}

func outboundBase(s Server, xrayPort int) (m, error) {
	s = applyHostOverride(s)
	if s.Host == "" || s.Port == 0 {
		return nil, errors.New("не задан сервер: вставь ссылку hysteria2://, vless://, trojan:// или ss:// на вкладке «Подключение»")
	}
	sni := s.SNI
	if sni == "" && s.Network == "ws" && s.WSHost != "" {
		// ссылка без sni, но с Host: за CDN (Cloudflare) сертификат выбирается по SNI, а не по Host, и IP в SNI не работает
		sni = s.WSHost
	}
	if sni == "" {
		sni = s.Host
	}
	if needsXray(s) {
		// transport is handled by a local Xray-core process that exposes SOCKS5
		return m{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": xrayPort, "version": "5"}, nil
	}
	switch s.Type {
	case "hysteria2":
		o := m{"type": "hysteria2", "tag": "proxy", "server": s.Host, "server_port": s.Port, "password": s.Password}
		if hp := normHop(s.HopPorts); len(hp) > 0 {
			delete(o, "server_port")
			o["server_ports"] = hp
			o["hop_interval"] = "30s"
		}
		if s.ObfsPassword != "" {
			o["obfs"] = m{"type": "salamander", "password": s.ObfsPassword}
		}
		o["tls"] = m{"enabled": true, "server_name": sni, "insecure": s.Insecure}
		return o, nil
	case "shadowsocks":
		return m{"type": "shadowsocks", "tag": "proxy", "server": s.Host, "server_port": s.Port, "method": s.Method, "password": s.Password}, nil
	case "trojan":
		o := m{"type": "trojan", "tag": "proxy", "server": s.Host, "server_port": s.Port, "password": s.Password}
		if s.Security != "none" {
			tls := m{"enabled": true, "server_name": sni}
			if s.Insecure {
				tls["insecure"] = true
			}
			if s.Fingerprint != "" {
				tls["utls"] = m{"enabled": true, "fingerprint": s.Fingerprint}
			}
			o["tls"] = tls
		}
		if s.Network == "ws" {
			path := s.WSPath
			if path == "" {
				path = "/"
			}
			h := s.WSHost
			if h == "" {
				h = sni
			}
			o["transport"] = m{"type": "ws", "path": path, "headers": m{"Host": h}}
		}
		return o, nil
	case "vless":
		o := m{"type": "vless", "tag": "proxy", "server": s.Host, "server_port": s.Port, "uuid": s.UUID, "packet_encoding": "xudp"}
		if s.Flow != "" && s.Network != "ws" {
			o["flow"] = s.Flow
		}
		switch s.Security {
		case "tls", "reality":
			tls := m{"enabled": true, "server_name": sni}
			if s.Insecure {
				tls["insecure"] = true
			}
			fp := s.Fingerprint
			if s.Security == "reality" && fp == "" {
				fp = "chrome"
			}
			if fp != "" {
				tls["utls"] = m{"enabled": true, "fingerprint": fp}
			}
			if s.Security == "reality" {
				tls["reality"] = m{"enabled": true, "public_key": s.PublicKey, "short_id": s.ShortID}
			}
			o["tls"] = tls
		}
		if s.Network == "ws" {
			path := s.WSPath
			if path == "" {
				path = "/"
			}
			t := m{"type": "ws", "path": path}
			h := s.WSHost
			if h == "" {
				h = sni
			}
			t["headers"] = m{"Host": h}
			o["transport"] = t
		}
		return o, nil
	}
	return nil, errors.New("неизвестный тип сервера: " + s.Type)
}

// serverKey is how a saved server is named in the UI and in groupServers.
func serverKey(s Server) string {
	if s.Name != "" {
		return s.Name
	}
	return s.Host
}

// narrowerThan: адреса из want, которые лежат внутри какого-то из broad (поддомены), но не равны им.
func narrowerThan(want, broad []string) []string {
	var out []string
	for _, d := range want {
		for _, b := range broad {
			if d != b && strings.HasSuffix(d, "."+b) {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

// fpOverride: каким браузером «представляться» при TLS. По разборам блокировок 2026 года отпечаток Chrome — один из
// признаков, по которым провайдер «замораживает» VLESS, поэтому для подписки сервиса по умолчанию Firefox.
// "" — оставить как в ссылке.
func fpOverride(st Settings) string {
	switch st.TLSFingerprint {
	case "", "auto":
		if serviceOK(st) {
			return "firefox"
		}
		return ""
	case "link":
		return ""
	case "firefox", "edge", "chrome", "safari":
		return st.TLSFingerprint
	}
	return ""
}

// pathsFor: другие пути к текущему серверу — его копии с другим адресом (ретрансляторы «… (через Питер)», запасные
// адреса). Копия узнаётся по тем же протоколу, порту и ключам: бот меняет в ней только адрес.
func pathsFor(st Settings) []Server {
	cur := st.Server
	if cur.Host == "" || cur.UUID == "" && cur.Password == "" {
		return nil
	}
	var out []Server
	base := pathBase(cur.Name)
	for _, p := range st.Profiles {
		if p.Gone || p.Host == cur.Host && p.Port == cur.Port || p.Type != cur.Type || p.UUID != cur.UUID ||
			p.Password != cur.Password || p.Network != cur.Network || p.Security != cur.Security {
			continue
		}
		// тот же вход: тот же порт или то же имя («vless-2083 (443)» — копия входа vless-2083 на порту 443)
		if p.Port != cur.Port && (base == "" || pathBase(p.Name) != base) {
			continue
		}
		dup := false
		for _, o := range out {
			if o.Host == p.Host && o.Port == p.Port {
				dup = true
			}
		}
		if !dup && len(out) < 4 {
			out = append(out, p)
		}
	}
	return append(out, protocolFallbacks(st, out)...)
}

// protocolFallbacks: тот же сервер другим протоколом (обычно Hysteria2 по UDP) — на случай, когда провайдер «замораживает»
// сам протокол (VLESS), и падают сразу все его пути. Берётся вход из той же подписки на том же адресе или ретрансляторе.
func protocolFallbacks(st Settings, paths []Server) []Server {
	cur := st.Server
	if !cur.FromSub {
		return nil
	}
	hosts := map[string]bool{cur.Host: true}
	for _, p := range paths {
		hosts[p.Host] = true
	}
	var out []Server
	for _, want := range []string{"hysteria2", "vless"} {
		for _, p := range st.Profiles {
			if len(out) >= 2 {
				return out
			}
			if p.Gone || !p.FromSub || p.Type == cur.Type || p.Type != want || !hosts[p.Host] || needsXray(p) {
				continue
			}
			if p.Type == "vless" && p.Security != "reality" {
				continue // запасным берём только Reality: ws/CDN-входы через ретранслятор не работают
			}
			dup := false
			for _, o := range out {
				dup = dup || o.Host == p.Host && o.Port == p.Port
			}
			if !dup {
				out = append(out, p)
			}
		}
	}
	return out
}

// currentPath: по какому пути сейчас идёт трафик при «Нескольких путях» — имя сервера-копии («… (через Питер)»)
// или имя самого сервера. Пусто, если путей нет или ядро не ответило.
func currentPath(st Settings) string {
	paths := pathsFor(st)
	if !st.MultiPath || st.AutoBest || len(paths) == 0 || !serviceOK(st) {
		return ""
	}
	var g struct {
		Now string `json:"now"`
	}
	if clashGet(st, "/proxies/proxy", &g) != nil || !strings.HasPrefix(g.Now, "path-") {
		return ""
	}
	i, err := strconv.Atoi(strings.TrimPrefix(g.Now, "path-"))
	if err != nil || i > len(paths) {
		return ""
	}
	if i == 0 {
		return st.Server.Name
	}
	return paths[i-1].Name
}

var rePathSuffix = regexp.MustCompile(`\s*\((через [^)]+|запас: [^)]+|\d{2,5})\)\s*$`)

// pathBase: имя входа без пометок «(через Питер)», «(запас: …)» и «(443)».
func pathBase(name string) string {
	for {
		n := rePathSuffix.ReplaceAllString(name, "")
		if n == name {
			return strings.TrimSpace(n)
		}
		name = n
	}
}

// allServers returns the active server plus the saved ones (deduplicated, at most 8).
func allServers(st Settings) []Server {
	var out []Server
	add := func(s Server) {
		if s.Host == "" || s.Port == 0 {
			return
		}
		for _, o := range out {
			if sameServer(o, s) {
				return
			}
		}
		if len(out) < 8 {
			out = append(out, s)
		}
	}
	add(st.Server)
	for _, p := range st.Profiles {
		// a server that left the subscription (inbound switched off) must not take one of the 8 slots of live ones
		if !p.Gone {
			add(p)
		}
	}
	return out
}

// fragFor: whether TLS fragmentation is on for this server (its own choice wins over the global switch).
func fragFor(st Settings, s Server) bool {
	switch s.Frag {
	case "on":
		return true
	case "off":
		return false
	}
	return st.Fragment
}

// fragEligible: a TLS-over-TCP outbound where splitting the ClientHello makes sense.
func fragEligible(o m) bool {
	ty, _ := o["type"].(string)
	if ty != "vless" && ty != "trojan" {
		return false
	}
	t, ok := o["tls"].(m)
	if !ok {
		return false
	}
	_, reality := t["reality"]
	return !reality
}

// applyFragment splits the TLS ClientHello so simple stream-throttling DPI cannot read it.
func applyFragment(o m) {
	// QUIC based outbounds have no TCP ClientHello to split.
	if ty, _ := o["type"].(string); ty == "hysteria2" || ty == "tuic" || ty == "hysteria" {
		return
	}
	if t, ok := o["tls"].(m); ok {
		t["fragment"] = true
		t["fragment_fallback_delay"] = "500ms"
	}
}

// groupOf lists the catalog services of a group that are switched on.
func collectGroup(st Settings, group string) (geos, domains, cidrs, apps []string) {
	for _, svc := range catalog {
		if svc.Group != group || !st.Services[svc.ID] {
			continue
		}
		for _, g := range svc.Geosite {
			geos = append(geos, "geosite-"+g)
		}
		domains = append(domains, svc.Domains...)
		cidrs = append(cidrs, svc.CIDRs...)
		apps = append(apps, svc.Apps...)
	}
	return uniq(geos), uniq(domains), uniq(cidrs), uniq(apps)
}

// probe users select the exit of a local test proxy (see probe.go).
const probeUserRoute = "route" // follows the routing rules, like a browser
const probeUserProxy = "proxy" // forced through the active server
const probeUserDirect = "direct"

// collect gathers everything that must go through the proxy.
func collect(st Settings) (geos, domains, cidrs, apps []string) {
	for _, svc := range catalog {
		if !st.Services[svc.ID] {
			continue
		}
		for _, g := range svc.Geosite {
			geos = append(geos, "geosite-"+g)
		}
		domains = append(domains, svc.Domains...)
		cidrs = append(cidrs, svc.CIDRs...)
		apps = append(apps, svc.Apps...)
	}
	domains = append(domains, cleanList(st.CustomDomains, normDomain)...)
	cidrs = append(cidrs, cleanList(st.CustomCIDRs, normCIDR)...)
	apps = append(apps, cleanList(st.ProxyApps, normApp)...)
	return uniq(geos), uniq(domains), uniq(cidrs), uniq(apps)
}

// neededTags lists the rule-set tags the current settings use.
func neededTags(st Settings) []string {
	geos, _, _, _ := collect(st)
	tags := append([]string{}, geos...)
	if st.BlockedRU {
		tags = append(tags, "ru-blocked-domains", "ru-blocked-ip")
	}
	if st.AdBlock {
		tags = append(tags, adsTag)
	}
	sort.Strings(tags)
	return tags
}

func filterTags(in []string, skip map[string]bool) []string {
	var out []string
	for _, t := range in {
		if !skip[t] {
			out = append(out, t)
		}
	}
	return out
}

// buildConfig produces the sing-box configuration for the given settings.
// skip lists rule-sets that could not be downloaded; they are left out.
func buildConfig(st Settings, dataDir string, skip map[string]bool) (m, error) {
	st = withCustomLists(st, dataDir)
	proxyOut, err := outboundFor(st.Server, st.XrayPort)
	if err != nil {
		return nil, err
	}
	if fragFor(st, st.Server) {
		applyFragment(proxyOut)
	}
	pinOutbound(proxyOut)
	// one outbound per saved server: used by auto-select, per-group servers and the test proxy;
	// plus "ways" (fragmentation / multiplex flipped) that the auto-tuner measures
	servers := allServers(st)
	exits := serverExits(st, servers)
	var extra []m
	var extraTags []string
	tagOf := map[string]string{} // serverKey -> outbound tag
	for _, e := range exits {
		extra = append(extra, e.Out)
		if e.Kind == "" {
			extraTags = append(extraTags, e.Tag)
			if _, dup := tagOf[serverKey(servers[e.Server])]; !dup {
				tagOf[serverKey(servers[e.Server])] = e.Tag
			}
		}
	}
	outbounds := []m{proxyOut, {"type": "direct", "tag": "direct"}}
	paths := pathsFor(st)
	service := serviceOK(st)
	if !(st.AutoBest && len(extraTags) >= 2 && service) && st.MultiPath && service && len(paths) > 0 && !needsXray(st.Server) {
		// «Несколько путей»: тот же сервер напрямую и через ретрансляторы. Ядро проверяет пути каждые 15 секунд и ведёт
		// трафик по живому; при смене пути зависшие соединения обрываются, и программы сразу переподключаются.
		proxyOut["tag"] = "path-0"
		tags := []string{"path-0"}
		var alt []m
		for i, sv := range paths {
			o, err := outboundFor(sv, st.XrayPort)
			if err != nil {
				continue
			}
			if fragFor(st, sv) {
				applyFragment(o)
			}
			pinOutbound(o)
			o["tag"] = "path-" + itoa(i+1)
			tags = append(tags, o["tag"].(string))
			alt = append(alt, o)
		}
		if len(alt) > 0 {
			outbounds = append([]m{proxyOut, {"type": "direct", "tag": "direct"}, {
				"type": "urltest", "tag": "proxy", "outbounds": tags,
				"url": "https://www.gstatic.com/generate_204", "interval": "15s", "tolerance": 80, "idle_timeout": "30m",
				"interrupt_exist_connections": true,
			}}, alt...)
		} else {
			proxyOut["tag"] = "proxy"
		}
	}
	if st.AutoBest && service && len(extraTags) >= 2 && !needsXray(st.Server) {
		// the group answers to "proxy": the fastest alive server carries the traffic
		proxyOut["tag"] = "proxy-main"
		outbounds = []m{proxyOut, {"type": "direct", "tag": "direct"}, {
			"type": "urltest", "tag": "proxy", "outbounds": extraTags,
			"url": "https://www.gstatic.com/generate_204", "interval": "1m", "tolerance": 60, "idle_timeout": "30m",
		}}
	}
	outbounds = append(outbounds, extra...)
	if fp := fpOverride(st); fp != "" {
		for _, o := range outbounds {
			if tag, _ := o["tag"].(string); strings.HasSuffix(tag, "-"+kindFP1) || strings.HasSuffix(tag, "-"+kindFP2) {
				continue // «способы» автоподбора с другими отпечатками остаются как есть
			}
			if t, ok := o["tls"].(m); ok && t["enabled"] == true {
				t["utls"] = m{"enabled": true, "fingerprint": fp}
			}
		}
	}

	_, domains, cidrs, apps := collect(st)
	allSets := filterTags(neededTags(st), skip)
	var routeSets []string
	adOn := false
	for _, t := range allSets {
		if t == adsTag {
			adOn = true // список рекламы не «через сервер»: по нему блокируем
			continue
		}
		routeSets = append(routeSets, t)
	}
	var dnsSets []string
	for _, t := range routeSets {
		if t != "ru-blocked-ip" {
			dnsSets = append(dnsSets, t)
		}
	}

	// rule-set definitions: local files that we download and refresh ourselves
	var ruleSets []m
	for _, tag := range allSets {
		ruleSets = append(ruleSets, m{"tag": tag, "type": "local", "format": "binary", "path": ruleSetPath(dataDir, tag)})
	}

	// DNS
	dnsRules := []m{}
	var dnsHosts []string
	for _, sv := range allServers(st) {
		if net.ParseIP(sv.Host) == nil {
			dnsHosts = append(dnsHosts, sv.Host)
		}
	}
	if len(dnsHosts) > 0 {
		dnsRules = append(dnsRules, m{"domain": uniq(dnsHosts), "server": "dns-local"})
	}
	// FakeIP (smart mode only): sites that go through the server get a placeholder address at once,
	// the real lookup happens on the server side — no DNS round-trip over a slow link.
	proxied := "dns-remote"
	useFake := st.FakeIP && !effectiveGlobal(st, time.Now())
	if useFake {
		proxied = "dns-fake"
	}
	if len(dnsSets) > 0 {
		dnsRules = append(dnsRules, m{"rule_set": dnsSets, "server": proxied})
	}
	if len(domains) > 0 {
		dnsRules = append(dnsRules, m{"domain_suffix": domains, "server": proxied})
	}
	// echo-IP hosts used by the leak test: one is always direct, one always through the server
	dnsRules = append([]m{{"domain": leakProxyHosts, "server": "dns-remote"}}, dnsRules...)
	directDomains := cleanList(st.DirectDomains, normDomain)
	global := effectiveGlobal(st, time.Now())
	if global {
		directDomains = append(directDomains, "ru", "su", "xn--p1ai")
	}
	if len(directDomains) > 0 {
		// direct domains must resolve locally, before any remote rule
		dnsRules = append([]m{{"domain_suffix": directDomains, "server": "dns-local"}}, dnsRules...)
	}
	if adOn {
		// реклама и трекеры: имя «не существует» — браузер и программы просто не загружают такие блоки.
		// Если в программе работает счётчик, ответ даёт он (и считает), иначе ядро отвечает само.
		act := m{"action": "predefined", "rcode": "NXDOMAIN"}
		if p := adDNSPort.Load(); p > 0 {
			act = m{"server": "dns-ads"}
		}
		dnsRules = append([]m{adMatch(st, act)}, dnsRules...)
	}
	if st.BlockIPv6 {
		// answer AAAA with an empty result so apps do not even try IPv6
		dnsRules = append([]m{{"query_type": []string{"AAAA"}, "action": "predefined", "rcode": "NOERROR"}}, dnsRules...)
	}
	localSrv := m{"type": "udp", "tag": "dns-local", "server": st.DNSLocal}
	switch st.DNSDoH {
	case "cloudflare":
		localSrv = m{"type": "https", "tag": "dns-local", "server": "1.1.1.1", "path": "/dns-query"}
	case "google":
		localSrv = m{"type": "https", "tag": "dns-local", "server": "8.8.8.8", "path": "/dns-query"}
	}
	dns := m{
		"servers": []m{
			localSrv,
			{"type": "tcp", "tag": "dns-remote", "server": st.DNSRemote, "detour": "proxy"},
		},
		"final": map[bool]string{true: "dns-remote", false: "dns-local"}[global],
	}
	dns["reverse_mapping"] = true
	if useFake {
		dns["servers"] = append(dns["servers"].([]m), m{"type": "fakeip", "tag": "dns-fake", "inet4_range": "198.18.0.0/15"})
	}
	if adOn {
		if p := adDNSPort.Load(); p > 0 {
			dns["servers"] = append(dns["servers"].([]m), m{"type": "udp", "tag": "dns-ads", "server": "127.0.0.1", "server_port": int(p)})
		}
	}
	if len(dnsRules) > 0 {
		dns["rules"] = dnsRules
	}

	// routing rules (order matters)
	rules := []m{
		// Browsers open idle pre-connect sockets that send nothing for a while: a longer sniff window
		// plus the DNS reverse mapping still gives such connections a domain to route by,
		// otherwise they fall through to "direct" by bare IP (YouTube thumbnails, Gemini).
		{"action": "sniff", "timeout": "1s"},
		{"protocol": "dns", "action": "hijack-dns"},
	}
	if adOn {
		// программы со своим DNS (DoH в браузере) обходят первый слой: режем соединение по имени из sniff
		rules = append(rules, adMatch(st, m{"action": "reject"}))
	}
	if st.RejectQUIC {
		rules = append(rules, m{"protocol": "quic", "action": "reject"})
	}
	rules = append(rules, m{"ip_is_private": true, "outbound": "direct"})
	rules = append(rules, m{"domain": leakProxyHosts, "outbound": "proxy"}, m{"domain": []string{leakDirectHost, leakV6Host}, "outbound": "direct"})
	if needsXray(st.Server) {
		// Xray's own connection to the server must not go back into the tunnel
		rules = append(rules, m{"process_name": []string{"xray.exe"}, "outbound": "direct"})
	}
	// the test proxy (probe.go) picks the exit by user name
	rules = append([]m{
		{"auth_user": []string{probeUserProxy}, "outbound": "proxy"},
		{"auth_user": []string{probeUserDirect}, "outbound": "direct"},
	}, rules...)
	for _, e := range exits {
		rules = append([]m{{"auth_user": []string{e.User}, "outbound": e.Tag}}, rules...)
	}
	var hostDomains, hostIPs []string
	// все адреса серверов подписки, а не только первые 8: ретрансляторы (Питер, Стокгольм…) тоже должны идти напрямую,
	// иначе обращение к ним (проверка, ssh) ушло бы в туннель
	for _, sv := range append([]Server{st.Server}, st.Profiles...) {
		if sv.Host == "" {
			continue
		}
		if net.ParseIP(sv.Host) != nil {
			hostIPs = append(hostIPs, sv.Host+"/32")
		} else {
			hostDomains = append(hostDomains, sv.Host)
		}
	}
	if len(hostIPs) > 0 {
		rules = append(rules, m{"ip_cidr": uniq(hostIPs), "outbound": "direct"})
	}
	if len(hostDomains) > 0 {
		rules = append(rules, m{"domain": uniq(hostDomains), "outbound": "direct"})
	}
	directApps := append(append([]string(nil), st.DirectApps...), builtinDirectApps...)
	if st.GameMode {
		directApps = append(append([]string(nil), directApps...), st.GameApps...)
	}
	if da := cleanList(directApps, normApp); len(da) > 0 {
		rules = append(rules, m{"process_name": da, "outbound": "direct"})
	}
	if len(directDomains) > 0 {
		// «своё напрямую» шире адреса сервиса (googleapis.com ⊃ discord-attachments-…googleapis.com): более точный
		// адрес сервиса важнее, иначе, например, картинки в Discord не отправлялись
		if ex := narrowerThan(domains, directDomains); len(ex) > 0 {
			rules = append(rules, m{"domain_suffix": ex, "outbound": "proxy"})
		}
		rules = append(rules, m{"domain_suffix": directDomains, "outbound": "direct"})
	}
	// groups pinned to their own server (e.g. AI services via a US server)
	groupSeen := map[string]bool{}
	for _, svc := range catalog {
		g := svc.Group
		key := st.GroupServers[g]
		tag := tagOf[key]
		if key == "" || tag == "" || groupSeen[g] {
			continue
		}
		groupSeen[g] = true
		gg, gd, gc, ga := collectGroup(st, g)
		gtags := filterTags(gg, skip)
		if len(ga) > 0 {
			rules = append(rules, m{"process_name": ga, "outbound": tag})
		}
		if len(gc) > 0 {
			rules = append(rules, m{"ip_cidr": gc, "outbound": tag})
		}
		if len(gtags) > 0 {
			rules = append(rules, m{"rule_set": gtags, "outbound": tag})
		}
		if len(gd) > 0 {
			rules = append(rules, m{"domain_suffix": gd, "outbound": tag})
		}
	}
	if len(apps) > 0 {
		rules = append(rules, m{"process_name": apps, "outbound": "proxy"})
	}
	if len(cidrs) > 0 {
		rules = append(rules, m{"ip_cidr": cidrs, "outbound": "proxy"})
	}
	if len(routeSets) > 0 {
		rules = append(rules, m{"rule_set": routeSets, "outbound": "proxy"})
	}
	if len(domains) > 0 {
		rules = append(rules, m{"domain_suffix": domains, "outbound": "proxy"})
	}

	if st.BlockIPv6 {
		// the tunnel has no IPv6 uplink: refuse it so nothing leaks around the VPN
		rules = append(rules, m{"ip_cidr": []string{"::/0"}, "action": "reject"})
	}

	route := m{
		"rules":                   rules,
		"final":                   map[bool]string{true: "proxy", false: "direct"}[global],
		"auto_detect_interface":   true,
		"find_process":            true,
		"default_domain_resolver": m{"server": "dns-local", "strategy": "ipv4_only"},
	}
	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}

	tunAddr := []string{"172.19.0.1/30"}
	if st.BlockIPv6 {
		tunAddr = append(tunAddr, "fdfe:dcba:9876::1/126")
	}
	cfg := m{
		"log": m{"level": st.LogLevel, "output": filepath.Join(dataDir, "box.log"), "timestamp": true},
		"dns": dns,
		"inbounds": []m{{
			"type": "tun", "tag": "tun-in", "address": tunAddr,
			"auto_route": true, "strict_route": true, "stack": "mixed",
		}, probeInbound(st, exits)},
		"outbounds": outbounds,
		"route":     route,
		"experimental": m{
			"cache_file": m{"enabled": true, "path": filepath.Join(dataDir, "cache.db")},
			"clash_api": m{
				"external_controller": "127.0.0.1:" + itoa(st.APIPort),
				"secret":              st.APISecret,
			},
		},
	}
	return cfg, nil
}

func configBytes(st Settings, dataDir string, skip map[string]bool) ([]byte, error) {
	cfg, err := buildConfig(st, dataDir, skip)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func configHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// fullHash covers everything that requires a restart when changed.
func fullHash(st Settings, dataDir string, skip map[string]bool) string {
	b, err := configBytes(st, dataDir, skip)
	if err != nil {
		return ""
	}
	b = append(b, ruleFilesStamp(st, dataDir, skip)...)
	if needsXray(st.Server) {
		if x, err := xrayConfigBytes(st, dataDir); err == nil {
			b = append(b, x...)
		}
	}
	return configHash(b)
}

// builtinDirectApps always go direct: the Steam client talks to its own service and to Valve servers,
// and routing those through the tunnel breaks the Steam Client Service on some setups.
var builtinDirectApps = []string{"steam.exe", "steamwebhelper.exe", "steamservice.exe", "gameoverlayui.exe", "steamerrorreporter.exe"}

const adsTag = "geosite-category-ads-all"

// adMatch: правило «это реклама» с действием act; сайты из исключений не трогаем.
func adMatch(st Settings, act m) m {
	allow := cleanList(st.AdAllow, normDomain)
	if len(allow) == 0 {
		r := m{"rule_set": []string{adsTag}}
		for k, v := range act {
			r[k] = v
		}
		return r
	}
	r := m{"type": "logical", "mode": "and", "rules": []m{
		{"rule_set": []string{adsTag}},
		{"domain_suffix": allow, "invert": true},
	}}
	for k, v := range act {
		r[k] = v
	}
	return r
}
