package main

import (
	"archive/zip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

func sameServer(a, b Server) bool {
	return a.Type == b.Type && a.Host == b.Host && a.Port == b.Port &&
		a.UUID == b.UUID && a.Password == b.Password && a.Network == b.Network
}

func profileIndex(st Settings) int {
	for i, p := range st.Profiles {
		if sameServer(p, st.Server) {
			return i
		}
	}
	return -1
}

// addProfiles appends servers that are not in the list yet and returns how many were new.
func addProfiles(st *Settings, list []Server) int {
	n := 0
	for _, s := range list {
		dup := false
		for _, p := range st.Profiles {
			if sameServer(p, s) {
				dup = true
				break
			}
		}
		if !dup {
			st.Profiles = append(st.Profiles, s)
			n++
		}
	}
	return n
}

// sameEndpoint: the same server entry even if its credentials changed (reset UUID/password in the panel).
func sameEndpoint(a, b Server) bool {
	return a.Type == b.Type && a.Host == b.Host && a.Port == b.Port && a.Network == b.Network && a.Name == b.Name
}

// syncProfiles merges servers from a subscription: new ones are added, ones whose credentials changed are
// updated in place (keeping the local tuning), and stale copies with old credentials are dropped.
func syncProfiles(st *Settings, list []Server) (added, updated int) {
	return syncProfilesOpt(st, list, true)
}

// syncProfilesOpt is syncProfiles; fromSub=false is for links the user pasted by hand: they are never marked as
// coming from the subscription, so a later refresh cannot flag them as gone.
func syncProfilesOpt(st *Settings, list []Server, fromSub bool) (added, updated int) {
	for _, s := range list {
		s.FromSub, s.Gone = fromSub, false
		first := -1
		for i := 0; i < len(st.Profiles); i++ {
			p := st.Profiles[i]
			if !sameEndpoint(p, s) {
				continue
			}
			if first < 0 {
				first = i
				if fromSub {
					st.Profiles[i].FromSub, st.Profiles[i].Gone = true, false
				}
				if !sameServer(p, s) {
					if sameServer(st.Server, p) {
						keep := st.Server
						st.Server = s
						st.Server.Frag, st.Server.Mux = keep.Frag, keep.Mux
					}
					s2 := s
					s2.Frag, s2.Mux = p.Frag, p.Mux
					s2.FromSub, s2.Gone = p.FromSub || fromSub, p.Gone && !fromSub
					st.Profiles[i] = s2
					updated++
				}
				continue
			}
			// a second entry for the same endpoint: it is a stale copy from before the reset
			if sameServer(st.Server, p) {
				st.Server = st.Profiles[first]
			}
			st.Profiles = append(st.Profiles[:i], st.Profiles[i+1:]...)
			i--
			updated++
		}
		if first < 0 {
			// the inbound was only renamed in the panel: same address and credentials, new name
			for i := range st.Profiles {
				p := st.Profiles[i]
				if sameServer(p, s) && p.Name != s.Name {
					if sameServer(st.Server, p) {
						st.Server.Name = s.Name
					}
					st.Profiles[i].Name = s.Name
					if fromSub {
						st.Profiles[i].FromSub, st.Profiles[i].Gone = true, false
					}
					first = i
					updated++
					break
				}
			}
		}
		if first < 0 {
			st.Profiles = append(st.Profiles, s)
			added++
		}
	}
	if fromSub {
		markGone(st, list)
	}
	return
}

// markGone flags servers that came from the subscription but are no longer in it (an inbound was switched off on the
// server). They are kept, not deleted: the user decides, and automatic switching skips them. An empty list is never
// trusted (a broken answer must not mark everything).
func markGone(st *Settings, list []Server) {
	if len(list) == 0 {
		return
	}
	for i := range st.Profiles {
		p := &st.Profiles[i]
		if !p.FromSub {
			continue
		}
		found := false
		for _, s := range list {
			if sameEndpoint(*p, s) {
				found = true
				break
			}
		}
		p.Gone = !found
	}
}

var errEmptySub = errors.New("в подписке не нашлось ни одного сервера: возможно, доступ закончился или адрес подписки неверный")

// parseLinks understands several links (one per line) or a base64 subscription body.
func parseLinks(text string) (list []Server, skipped int) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	if !strings.Contains(text, "://") {
		clean := strings.Join(strings.Fields(text), "")
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(clean); err == nil {
				text = string(b)
				break
			}
		}
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		s, err := parseLink(line)
		if err != nil {
			skipped++
			continue
		}
		if s.Name == "" {
			s.Name = s.Host
		}
		list = append(list, s)
	}
	return
}

func fetchSubscription(url string) (string, error) {
	text, _, err := fetchSubscriptionMeta(url)
	return text, err
}

func fetchSubscriptionMeta(url string) (string, *SubMeta, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "", nil, errors.New("нужна ссылка вида https://…")
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "v2rayN/6.42")
	setDeviceHeaders(req)
	c := &http.Client{Timeout: 20 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return "", nil, errors.New("не удалось скачать подписку: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", nil, fmt.Errorf("сервер подписки ответил %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return string(b), parseSubMeta(resp.Header, url), nil
}

// fetchSubWithMirrors reads the subscription; when the main address fails, it tries the mirrors the server told us before.
func fetchSubWithMirrors(u string, prev *SubMeta) (string, *SubMeta, error) {
	text, meta, err := fetchSubscriptionMeta(u)
	if err == nil || prev == nil {
		return text, meta, err
	}
	for _, m := range prev.Mirrors {
		mu := mirrorURL(u, m)
		if mu == "" {
			continue
		}
		if t, mm, e := fetchSubscriptionMeta(mu); e == nil {
			if len(mm.Mirrors) == 0 {
				mm.Mirrors = prev.Mirrors
			}
			return t, mm, nil
		}
	}
	return "", nil, err
}

// POST /api/profiles {action: add|subscription|use|delete|save, text|url|index}
func (a *App) handleProfiles(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string `json:"action"`
		Text   string `json:"text"`
		URL    string `json:"url"`
		Index  int    `json:"index"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	msg := ""
	if in.Action == "smart" {
		// one input for everything: an http(s) address is a subscription, anything else is one or more server links
		t := strings.TrimSpace(in.Text)
		if t == "" {
			fail(w, 400, "вставь ссылку на сервер или подписку")
			return
		}
		if (strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://")) && !strings.ContainsAny(t, " \n\r\t") {
			in.Action, in.URL = "subscription", t
		} else {
			in.Action, in.Text = "add", t
		}
	}
	switch in.Action {
	case "refresh":
		u := a.st.SubURL
		if u == "" {
			fail(w, 400, "подписка не задана")
			return
		}
		prev := a.st.SubMeta
		a.mu.Unlock()
		text, meta, err := fetchSubWithMirrors(u, prev)
		a.mu.Lock()
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		list, _ := parseLinks(text)
		if len(list) == 0 {
			fail(w, 400, errEmptySub.Error())
			return
		}
		n, upd := syncProfiles(&a.st, list)
		meta.Updated, meta.Count = time.Now().Unix(), len(list)
		a.st.SubMeta = meta
		msg = fmt.Sprintf("Подписка обновлена, новых серверов: %d, обновлено: %d", n, upd)
	case "unsub":
		a.st.SubURL, a.st.SubMeta, a.st.SubAuto = "", nil, false
		msg = "Подписка отвязана, серверы остались в списке"
	case "add", "subscription":
		text := in.Text
		if in.Action == "subscription" {
			u := strings.TrimSpace(in.URL)
			a.mu.Unlock()
			t, meta, err := fetchSubscriptionMeta(u)
			a.mu.Lock()
			if err != nil {
				fail(w, 400, err.Error())
				return
			}
			text = t
			if l, _ := parseLinks(t); len(l) == 0 {
				fail(w, 400, errEmptySub.Error())
				return
			} else if n := subNotice(l); n != "" {
				fail(w, 400, strings.TrimLeft(n, "⚠ "))
				return
			} else if meta != nil {
				meta.Updated, meta.Count = time.Now().Unix(), len(l)
			}
			// only a subscription that really holds servers replaces the saved one
			a.st.SubURL, a.st.SubMeta = u, meta
		}
		list, skipped := parseLinks(text)
		if len(list) == 0 {
			fail(w, 400, "не нашёл ни одной подходящей ссылки (поддерживаются hysteria2://, vless://, trojan:// и ss://)")
			return
		}
		n, _ := syncProfilesOpt(&a.st, list, in.Action == "subscription")
		if a.st.Server.Host == "" {
			a.st.Server = list[0]
		}
		msg = fmt.Sprintf("Добавлено серверов: %d", n)
		if skipped > 0 {
			msg += fmt.Sprintf(", пропущено неподдерживаемых: %d", skipped)
		}
	case "auto":
		a.st.SubAuto = !a.st.SubAuto
		msg = map[bool]string{true: "Подписка будет обновляться сама раз в 6 часов", false: "Автообновление подписки выключено"}[a.st.SubAuto]
	case "save":
		if a.st.Server.Host == "" {
			fail(w, 400, "сначала задай сервер")
			return
		}
		s := a.st.Server
		if s.Name == "" {
			s.Name = s.Host
		}
		if addProfiles(&a.st, []Server{s}) == 0 {
			msg = "Этот сервер уже в списке"
		} else {
			msg = "Сервер добавлен в список"
		}
	case "test":
		list := append([]Server(nil), a.st.Profiles...)
		st := a.st
		a.mu.Unlock()
		running, _, _, _, _ := a.core.Info()
		o := pingOpts{VPN: running}
		if running {
			o.Dialers = physicalDialers(2 * time.Second)
			if cfg, err := os.ReadFile(filepath.Join(a.dataDir, "config.json")); err == nil {
				o.Tags = coreTags(cfg, list)
			}
			o.Delay = func(tag string) (int, error) { return clashDelay(st, tag, "https://www.gstatic.com/generate_204") }
		}
		res := pingProfiles(list, o)
		a.mu.Lock() // the deferred Unlock expects it held
		writeJSON(w, 200, map[string]any{"ok": true, "results": res})
		return
	case "use":
		if in.Index < 0 || in.Index >= len(a.st.Profiles) {
			fail(w, 400, "нет такого сервера")
			return
		}
		a.st.Server = a.st.Profiles[in.Index]
	case "delete":
		if in.Index < 0 || in.Index >= len(a.st.Profiles) {
			fail(w, 400, "нет такого сервера")
			return
		}
		a.st.Profiles = append(a.st.Profiles[:in.Index:in.Index], a.st.Profiles[in.Index+1:]...)
	default:
		fail(w, 400, "неизвестное действие")
		return
	}
	st := a.st
	if err := saveSettings(a.dataDir, st); err != nil {
		fail(w, 500, err.Error())
		return
	}
	st.APISecret, st.AppToken = "", ""
	writeJSON(w, 200, map[string]any{"ok": true, "message": msg, "settings": st})
}

// refreshSubscription re-reads the saved subscription and adds servers that are new. Returns how many.
func (a *App) refreshSubscription() (int, error) {
	a.mu.Lock()
	u, prev := a.st.SubURL, a.st.SubMeta
	a.mu.Unlock()
	if u == "" {
		return 0, errors.New("подписка не задана")
	}
	text, meta, err := fetchSubWithMirrors(u, prev)
	if err != nil {
		return 0, err
	}
	list, _ := parseLinks(text)
	if len(list) == 0 {
		return 0, errEmptySub
	}
	if note := subNotice(list); note != "" {
		// лимит устройств или устаревшая ссылка: серверы не трогаем (иначе все пометились бы пропавшими), показываем причину
		a.mu.Lock()
		if a.st.SubMeta != nil {
			m := *a.st.SubMeta
			m.Notice = strings.TrimLeft(note, "⚠ ")
			a.st.SubMeta = &m
			a.rev.Add(1)
		}
		st := a.st
		a.mu.Unlock()
		_ = saveSettings(a.dataDir, st)
		return 0, errors.New(strings.TrimLeft(note, "⚠ "))
	}
	a.mu.Lock()
	n, upd := syncProfiles(&a.st, list)
	n += upd
	if meta != nil {
		meta.Updated, meta.Count = time.Now().Unix(), len(list)
		a.st.SubMeta = meta
		a.rev.Add(1)
	}
	st := a.st
	if n > 0 {
		a.rev.Add(1)
	}
	a.mu.Unlock()
	if n > 0 || meta != nil {
		_ = saveSettings(a.dataDir, st)
	}
	return n, nil
}

func (a *App) subscriptionLoop() {
	time.Sleep(90 * time.Second)
	var lastRefresh time.Time
	for {
		if st := a.settings(); st.SubAuto && st.SubURL != "" && time.Since(lastRefresh) >= 6*time.Hour {
			lastRefresh = time.Now()
			if n, err := a.refreshSubscription(); err != nil {
				logf("subscription: %v", err)
			} else if n > 0 {
				a.notify(appName, fmt.Sprintf("Из подписки добавлено серверов: %d", n))
			}
		}
		a.checkSubAlerts()
		select {
		case <-a.quit:
			return
		case <-time.After(time.Hour):
		}
	}
}

type pingResult struct {
	Index int    `json:"index"`
	Ms    int    `json:"ms"` // -1 = no answer
	Note  string `json:"note,omitempty"`
}

// nextAlive is the index after from that is still in the subscription; when every other entry is gone it is simply
// the next one.
func nextAlive(list []Server, from int) int {
	n := len(list)
	for k := 1; k < n; k++ {
		j := ((from+k)%n + n) % n
		if !list[j].Gone {
			return j
		}
	}
	return ((from+1)%n + n) % n
}

// failoverNext switches to the next saved server. Returns its name.
func (a *App) failoverNext() (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.st.Failover || len(a.st.Profiles) < 2 {
		return "", false
	}
	i := profileIndex(a.st)
	next := nextAlive(a.st.Profiles, i)
	if a.st.SmartOrder && a.srv != nil {
		if ord := a.srv.order(a.st.Profiles, a.st.Server, a.net.get(), bucketOf(time.Now())); len(ord) > 0 {
			next = ord[0]
		}
	}
	a.st.Server = a.st.Profiles[next]
	a.rev.Add(1)
	_ = saveSettings(a.dataDir, a.st)
	n := a.st.Server.Name
	if n == "" {
		n = a.st.Server.Host
	}
	return n, true
}

// failoverSlow switches to another saved server because the current one is degraded.
// It prefers a different protocol (hysteria2 -> vless), otherwise takes the next one.
func (a *App) failoverSlow() (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.st.Failover || !a.st.SlowSwitch || len(a.st.Profiles) < 2 {
		return "", false
	}
	i := profileIndex(a.st)
	next := -1
	for k := 1; k < len(a.st.Profiles); k++ {
		j := (i + k + len(a.st.Profiles)) % len(a.st.Profiles)
		if a.st.Profiles[j].Type != a.st.Server.Type && !a.st.Profiles[j].Gone {
			next = j
			break
		}
	}
	if next < 0 {
		next = nextAlive(a.st.Profiles, i)
	}
	a.st.Server = a.st.Profiles[next]
	a.rev.Add(1)
	_ = saveSettings(a.dataDir, a.st)
	n := a.st.Server.Name
	if n == "" {
		n = a.st.Server.Host
	}
	return n, true
}

// ---- export / report ----

func maskServer(s Server) Server {
	m := func(v string) string {
		if v == "" {
			return ""
		}
		return "***"
	}
	s.Password, s.ObfsPassword, s.UUID, s.PublicKey, s.ShortID = m(s.Password), m(s.ObfsPassword), m(s.UUID), m(s.PublicKey), m(s.ShortID)
	return s
}

func (a *App) handleExport(w http.ResponseWriter, r *http.Request) {
	st := a.settings()
	b, _ := json.MarshalIndent(st, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="settings-backup.json"`)
	w.Write(b)
}

func (a *App) handleReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="report-`+time.Now().Format("2006-01-02-1504")+`.zip"`)
	a.writeReport(w)
}

// writeReport writes the diagnostic zip (secrets masked) to w.
func (a *App) writeReport(w io.Writer) {
	st := a.settings()
	st.APISecret = "***"
	if st.AppToken != "" {
		st.AppToken = "***"
	}
	if st.SubURL != "" {
		st.SubURL = "***"
	}
	if st.SubMeta != nil {
		m := *st.SubMeta
		m.Title = "***"
		st.SubMeta = &m
	}
	st.Server = maskServer(st.Server)
	st.Profiles = append([]Server(nil), st.Profiles...) // do not mask the live list
	for i := range st.Profiles {
		st.Profiles[i] = maskServer(st.Profiles[i])
	}
	zw := zip.NewWriter(w)
	defer zw.Close()
	add := func(name string, data []byte) {
		if f, err := zw.Create(name); err == nil {
			f.Write(data)
		}
	}
	sb, _ := json.MarshalIndent(st, "", "  ")
	add("settings.json", sb)
	if b, err := configBytes(a.settings(), a.dataDir, a.core.Skip()); err == nil {
		var cfg map[string]any
		if json.Unmarshal(b, &cfg) == nil {
			if exp, ok := cfg["experimental"].(map[string]any); ok {
				if c, ok := exp["clash_api"].(map[string]any); ok {
					c["secret"] = "***"
				}
			}
			if arr, ok := cfg["outbounds"].([]any); ok {
				for _, o := range arr {
					om, ok := o.(map[string]any)
					if !ok {
						continue
					}
					for _, key := range []string{"password", "uuid"} {
						if _, has := om[key]; has {
							om[key] = "***"
						}
					}
					if ob, ok := om["obfs"].(map[string]any); ok {
						ob["password"] = "***"
					}
					if t, ok := om["tls"].(map[string]any); ok {
						if rl, ok := t["reality"].(map[string]any); ok {
							rl["public_key"], rl["short_id"] = "***", "***"
						}
					}
				}
			}
			cb, _ := json.MarshalIndent(cfg, "", "  ")
			add("config.json", cb)
		}
	} else {
		add("config-error.txt", []byte(err.Error()))
	}
	running, _, up, _, _ := a.core.Info()
	info := fmt.Sprintf("app: %s\nwindows/go: %s %s\ntime: %s\nrunning: %v\nuptime: %s\nsing-box: %s\nhealth: %+v\nrulesets: %+v\n",
		appName, runtime.GOOS, runtime.Version(), time.Now().Format(time.RFC3339), running, up, a.core.Version(a.core.binPath(a.settings())), a.health.State, ruleSetStatus(a.settings(), a.dataDir))
	add("info.txt", []byte(info))
	if b, err := json.Marshal(a.links.snapshot()); err == nil {
		add("linklog.json", b) // журнал связи по путям за сутки (без адресов: только «напрямую», «через Питер»…)
	}
	for _, f := range []string{"box.log", "core.out", "xray.log", "xray.out"} {
		if t := tailFile(filepath.Join(a.dataDir, f), 200000); t != "" {
			// hide anything that looks like a secret
			add(f, []byte(redactSecrets(stripANSI(t), a.settings())))
		}
	}
}

var reUUIDLog = regexp.MustCompile(`(?i)\b[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\b`)

// redactSecrets hides every secret from the settings (passwords, keys, ids, subscription address) and any UUID in a log.
func redactSecrets(text string, st Settings) string {
	list := append([]Server{st.Server}, st.Profiles...)
	vals := []string{st.APISecret, st.SubURL, st.AppToken}
	for _, s := range list {
		vals = append(vals, s.Password, s.ObfsPassword, s.UUID, s.PublicKey, s.ShortID)
	}
	for _, v := range vals {
		if len(v) >= 6 {
			text = strings.ReplaceAll(text, v, "***")
		}
	}
	return reUUIDLog.ReplaceAllString(text, "***")
}
