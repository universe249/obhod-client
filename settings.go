package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type Server struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // hysteria2 | vless
	Host     string `json:"host"`
	Port     int    `json:"port"`
	SNI      string `json:"sni"`
	Insecure bool   `json:"insecure"`

	// hysteria2
	Password     string `json:"password"`
	ObfsPassword string `json:"obfsPassword"`
	HopPorts     string `json:"hopPorts"` // port hopping range, e.g. 20000-30000

	// vless
	Method      string `json:"method"` // shadowsocks cipher
	UUID        string `json:"uuid"`
	Flow        string `json:"flow"`
	Security    string `json:"security"` // tls | reality | none
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	Network     string `json:"network"` // tcp | ws
	WSPath      string `json:"wsPath"`
	WSHost      string `json:"wsHost"`

	// subscription bookkeeping: FromSub = the entry came from the subscription, Gone = the subscription no longer lists it
	FromSub bool `json:"fromSub,omitempty"`
	Gone    bool `json:"gone,omitempty"`

	// connection tweaks picked by the auto-tuner (see tune.go)
	Frag string `json:"frag,omitempty"` // "" = follow the global switch | on | off
	Mux  bool   `json:"mux,omitempty"`  // several streams over one connection

	// xhttp (served by Xray-core)
	XMode  string `json:"xMode"`
	XExtra string `json:"xExtra"`
	Spx    string `json:"spx"`
}

type Settings struct {
	Server          Server            `json:"server"`
	Profiles        []Server          `json:"profiles"` // saved servers
	Failover        bool              `json:"failover"` // switch to the next server when the current one is dead
	BlockIPv6       bool              `json:"ipv6Guard"`
	Mode            string            `json:"mode"` // smart (by lists) | global (everything through the server except .ru and direct lists)
	Services        map[string]bool   `json:"services"`
	BlockedRU       bool              `json:"blockedRu"`
	AdBlock         bool              `json:"adBlock"`       // блокировка рекламы и трекеров (список category-ads-all)
	Suggest         bool              `json:"suggest"`       // подсказывать сайты, которые не открываются напрямую («умный режим 2.0»)
	SuggestIgnore   []string          `json:"suggestIgnore"` // о каких сайтах больше не подсказывать
	AdAllow         []string          `json:"adAllow"`       // сайты, на которых рекламу не блокировать (если что-то сломалось)
	CustomDomains   []string          `json:"customDomains"`
	CustomCIDRs     []string          `json:"customCidrs"`  // extra IPs/subnets that go through the server
	IgnoredHints    []string          `json:"ignoredHints"` // suggestions the user dismissed
	DirectDomains   []string          `json:"directDomains"`
	ProxyApps       []string          `json:"proxyApps"`
	DirectApps      []string          `json:"directApps"`
	RejectQUIC      bool              `json:"rejectQuic"`
	DNSLocal        string            `json:"dnsLocal"`
	ReportURL       string            `json:"reportUrl"` // where diagnostics go (the bot); empty = default
	DNSDoH          string            `json:"dnsDoh"`    // "" = plain UDP to DNSLocal; cloudflare | google = DNS over HTTPS for ordinary sites
	DNSRemote       string            `json:"dnsRemote"`
	LogLevel        string            `json:"logLevel"`
	UIPort          int               `json:"uiPort"`
	APIPort         int               `json:"apiPort"`
	APISecret       string            `json:"apiSecret"`
	StartCore       bool              `json:"startCore"`        // start the tunnel when the app starts
	Expert          bool              `json:"expert,omitempty"` // show the "Инструменты" tab (log, connections, network checks)
	CorePath        string            `json:"corePath"`         // не используется с 6.3 (ядро встроено)
	XrayPath        string            `json:"xrayPath"`
	XrayPort        int               `json:"xrayPort"`
	Watchdog        bool              `json:"watchdog"`                  // watch the connection and restart when it breaks
	Notify          bool              `json:"notify"`                    // tray notifications
	TrayOpensWindow bool              `json:"trayOpensWindow,omitempty"` // щелчок по значку в трее открывает окно, а не мини-панель
	GlobalUntil     int64             `json:"globalUntil,omitempty"`     // «всё через сервер» на время: до какого момента (unix), 0 — выключено
	Hotkeys         map[string]string `json:"hotkeys"`                   // глобальные сочетания клавиш: действие -> "Ctrl+Alt+O"
	Schedule        []SchedRule       `json:"schedule"`                  // расписание: включить, выключить, сменить набор правил
	NetWatch        bool              `json:"netWatch"`                  // переподключаться при смене сети
	SmartOrder      bool              `json:"smartOrder"`                // запоминать, какой сервер лучше в какой сети
	Telemetry       string            `json:"telemetry"`                 // "" = ещё не спрашивали | on | off: анонимные отчёты об ошибках
	InstallID       string            `json:"installId"`                 // случайный номер установки для отчётов
	SubURL          string            `json:"subUrl"`                    // last subscription address
	SubMeta         *SubMeta          `json:"subMeta,omitempty"`         // what the subscription server told us (traffic, expiry, title)
	SubAuto         bool              `json:"subAuto"`                   // re-read it every few hours
	Fragment        bool              `json:"fragment"`                  // split the TLS ClientHello (helps against stream throttling)
	AutoBest        bool              `json:"autoBest"`                  // keep several servers and use the fastest alive one
	AppToken        string            `json:"appToken,omitempty"`        // выдан ботом при входе через Telegram: чат с поддержкой
	ChatSeen        int               `json:"chatSeen,omitempty"`        // последнее прочитанное сообщение поддержки
	MultiPath       bool              `json:"multiPath"`
	TLSFingerprint  string            `json:"tlsFingerprint,omitempty"` // auto | link | firefox | edge | chrome | safari          // «Несколько путей»: тот же сервер напрямую и через ретрансляторы, ядро держит живой путь
	FakeIP          bool              `json:"fakeIp"`                   // smart mode: proxied domains get fake addresses, the server resolves them
	AutoTune        bool              `json:"autoTune"`                 // when the link degrades, try servers and ways (fragmentation, mux) and keep the best
	GroupServers    map[string]string `json:"groupServers"`             // service group -> saved server that carries it
	SlowSwitch      bool              `json:"slowSwitch"`               // switch to another server when the connection is degraded, not only dead
	GameMode        bool              `json:"gameMode"`                 // GameApps temporarily go direct
	GameApps        []string          `json:"gameApps"`
	Presets         []Preset          `json:"presets"`     // saved rule sets the user can switch between
	SubAlerted      []string          `json:"subAlerted"`  // subscription warnings that were already shown
	CustomLists     []CustomList      `json:"customLists"` // domain lists connected by link
	AutoGame        bool              `json:"autoGame"`    // switch game mode on when a game from the list starts
}

func defaultSettings() Settings {
	s := Settings{
		Services:   map[string]bool{},
		BlockedRU:  true,
		RejectQUIC: true,
		DNSLocal:   "77.88.8.8",
		DNSRemote:  "1.1.1.1",
		LogLevel:   "info",
		Suggest:    true,
		UIPort:     17890,
		APIPort:    19090,
		XrayPort:   10808,
		Watchdog:   true,
		Notify:     true,
		Failover:   true,
		SlowSwitch: true,
		NetWatch:   true,
		MultiPath:  true,
		Hotkeys:    map[string]string{"toggle": "Ctrl+Alt+O"},
		SmartOrder: true,
	}
	for _, svc := range catalog {
		s.Services[svc.ID] = svc.Default
	}
	return s
}

var settingsMu sync.Mutex

func decodeSettings(b []byte) Settings {
	s := defaultSettings()
	_ = json.Unmarshal(b, &s)
	mapSecrets(&s, openString)
	return normalizeSettings(s)
}

func loadSettings(dir string) Settings {
	s := defaultSettings()
	b, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err == nil {
		s = decodeSettings(b)
	}
	return normalizeSettings(s)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func normalizeSettings(s Settings) Settings {
	if c, err := cleanHotkeys(s.Hotkeys); err == nil {
		s.Hotkeys = c
	} else {
		s.Hotkeys = map[string]string{}
	}
	s.Schedule = cleanSchedule(s.Schedule)
	s.CustomCIDRs = dedupe(s.CustomCIDRs)
	s.CustomDomains = dedupe(s.CustomDomains)
	s.IgnoredHints = dedupe(s.IgnoredHints)
	if s.Services == nil {
		s.Services = map[string]bool{}
	}
	if s.UIPort == 0 {
		s.UIPort = 17890
	}
	if s.APIPort == 0 {
		s.APIPort = 19090
	}
	if s.XrayPort == 0 {
		s.XrayPort = 10808
	}
	if s.DNSLocal == "" {
		s.DNSLocal = "77.88.8.8"
	}
	if s.DNSRemote == "" {
		s.DNSRemote = "1.1.1.1"
	}
	if s.LogLevel == "" {
		s.LogLevel = "info"
	}
	if s.APISecret == "" {
		s.APISecret = randHex(16)
	}
	return s
}

func saveSettings(dir string, s Settings) error {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	s.Profiles = append([]Server(nil), s.Profiles...) // never touch the caller's slice
	if secretsUnreadable.Load() {
		backupUnreadable(dir)
	}
	mapSecrets(&s, sealString)
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "settings.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "settings.json"))
}
