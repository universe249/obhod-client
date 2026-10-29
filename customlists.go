package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// CustomList is a domain list the user connected by link. Its domains go through the server or directly.
type CustomList struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Mode    string `json:"mode"` // proxy | direct
	Count   int    `json:"count"`
	Updated int64  `json:"updated"`
	Err     string `json:"err,omitempty"`
}

const (
	maxListBytes   = 6 << 20
	maxListDomains = 60000
	maxCustomLists = 8
)

func listsDir(dataDir string) string { return filepath.Join(dataDir, "lists") }

func listFile(dataDir, rawURL string) string {
	h := sha1.Sum([]byte(rawURL))
	return filepath.Join(listsDir(dataDir), hex.EncodeToString(h[:6])+".txt")
}

var domainRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$`)
var ipLikeRe = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)

// parseDomainList understands plain lists, hosts files, v2ray ("domain:", "full:"), adblock ("||x^")
// and the JSON form of a sing-box rule-set. Returns unique valid domains.
func parseDomainList(text string) ([]string, error) {
	text = strings.TrimPrefix(text, "\xef\xbb\xbf")
	if strings.HasPrefix(text, "SRS") {
		return nil, errors.New("это бинарный список sing-box (.srs), нужен текстовый список доменов")
	}
	var out []string
	seen := map[string]bool{}
	add := func(d string) {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, "*.")
		d = strings.TrimPrefix(d, "+.")
		d = strings.Trim(d, ".")
		if d == "" || ipLikeRe.MatchString(d) || !domainRe.MatchString(d) || seen[d] || len(d) > 253 {
			return
		}
		seen[d] = true
		out = append(out, d)
	}
	trim := strings.TrimSpace(text)
	if strings.HasPrefix(trim, "{") {
		var rs struct {
			Rules []struct {
				Domain       []string `json:"domain"`
				DomainSuffix []string `json:"domain_suffix"`
			} `json:"rules"`
		}
		if err := json.Unmarshal([]byte(trim), &rs); err != nil || len(rs.Rules) == 0 {
			return nil, errors.New("не удалось разобрать JSON-список")
		}
		for _, r := range rs.Rules {
			for _, d := range r.Domain {
				add(d)
			}
			for _, d := range r.DomainSuffix {
				add(d)
			}
		}
	} else {
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
				continue
			}
			if i := strings.IndexAny(line, "#"); i > 0 {
				line = strings.TrimSpace(line[:i])
			}
			switch {
			case strings.HasPrefix(line, "||"):
				add(strings.SplitN(strings.TrimPrefix(line, "||"), "^", 2)[0])
				continue
			case strings.HasPrefix(line, "domain:"), strings.HasPrefix(line, "full:"):
				add(line[strings.Index(line, ":")+1:])
				continue
			case strings.HasPrefix(line, "keyword:"), strings.HasPrefix(line, "regexp:"), strings.HasPrefix(line, "geosite:"):
				continue
			}
			f := strings.Fields(line)
			if len(f) >= 2 && ipLikeRe.MatchString(f[0]) { // hosts file
				for _, d := range f[1:] {
					add(d)
				}
				continue
			}
			if len(f) > 0 {
				add(strings.TrimSuffix(strings.SplitN(f[0], "/", 2)[0], "^"))
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("в списке не нашлось ни одного домена")
	}
	if len(out) > maxListDomains {
		out = out[:maxListDomains]
	}
	return out, nil
}

var listClient = &http.Client{Timeout: 25 * time.Second}

func validListURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", errors.New("нужна ссылка вида https://…")
	}
	return u.String(), nil
}

// fetchList downloads and stores a list, returns how many domains it holds.
func fetchList(dataDir, rawURL string) (int, error) {
	req, _ := http.NewRequest("GET", rawURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := listClient.Do(req)
	if err != nil {
		return 0, errors.New(shortErr(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, errors.New("сайт ответил " + resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil {
		return 0, errors.New(shortErr(err))
	}
	if len(b) > maxListBytes {
		return 0, errors.New("список больше 6 МБ")
	}
	domains, err := parseDomainList(string(b))
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(listsDir(dataDir), 0o755); err != nil {
		return 0, err
	}
	tmp := listFile(dataDir, rawURL) + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(domains, "\n")), 0o600); err != nil {
		return 0, err
	}
	return len(domains), os.Rename(tmp, listFile(dataDir, rawURL))
}

func readListFile(dataDir, rawURL string) []string {
	b, err := os.ReadFile(listFile(dataDir, rawURL))
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

// withCustomLists returns settings where the domains of the connected lists are added to the manual lists.
func withCustomLists(st Settings, dataDir string) Settings {
	if len(st.CustomLists) == 0 {
		return st
	}
	proxy := append([]string(nil), st.CustomDomains...)
	direct := append([]string(nil), st.DirectDomains...)
	for _, l := range st.CustomLists {
		d := readListFile(dataDir, l.URL)
		if l.Mode == "direct" {
			direct = append(direct, d...)
		} else {
			proxy = append(proxy, d...)
		}
	}
	st.CustomDomains, st.DirectDomains = proxy, direct
	return st
}

func (a *App) refreshList(i int) error {
	a.mu.Lock()
	if i < 0 || i >= len(a.st.CustomLists) {
		a.mu.Unlock()
		return errors.New("нет такого списка")
	}
	u := a.st.CustomLists[i].URL
	a.mu.Unlock()
	n, err := fetchList(a.dataDir, u)
	a.mu.Lock()
	defer a.mu.Unlock()
	for k := range a.st.CustomLists { // the list may have moved while we downloaded
		if a.st.CustomLists[k].URL != u {
			continue
		}
		if err != nil {
			a.st.CustomLists[k].Err = err.Error()
		} else {
			changed := a.st.CustomLists[k].Count != n || a.st.CustomLists[k].Err != ""
			a.st.CustomLists[k].Count, a.st.CustomLists[k].Err = n, ""
			a.st.CustomLists[k].Updated = time.Now().Unix()
			if changed {
				a.rev.Add(1)
			}
		}
	}
	_ = saveSettings(a.dataDir, a.st)
	return err
}

func (a *App) handleLists(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"lists": a.settings().CustomLists})
		return
	}
	var in struct {
		Action string `json:"action"`
		URL    string `json:"url"`
		Name   string `json:"name"`
		Mode   string `json:"mode"`
		Index  int    `json:"index"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	switch in.Action {
	case "add":
		u, err := validListURL(in.URL)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		mode := "proxy"
		if in.Mode == "direct" {
			mode = "direct"
		}
		a.mu.Lock()
		for _, l := range a.st.CustomLists {
			if l.URL == u {
				a.mu.Unlock()
				fail(w, 400, "такой список уже подключён")
				return
			}
		}
		if len(a.st.CustomLists) >= maxCustomLists {
			a.mu.Unlock()
			fail(w, 400, "можно подключить не больше 8 списков")
			return
		}
		a.mu.Unlock()
		n, err := fetchList(a.dataDir, u)
		if err != nil {
			fail(w, 400, "не удалось загрузить список: "+err.Error())
			return
		}
		name := strings.TrimSpace(in.Name)
		if name == "" {
			if pu, e := url.Parse(u); e == nil {
				name = pu.Host + pu.Path
				if len(name) > 50 {
					name = name[:50]
				}
			}
		}
		a.mu.Lock()
		a.st.CustomLists = append(a.st.CustomLists, CustomList{Name: name, URL: u, Mode: mode, Count: n, Updated: time.Now().Unix()})
		a.rev.Add(1)
		st := a.st
		a.mu.Unlock()
		if err := saveSettings(a.dataDir, st); err != nil {
			fail(w, 500, err.Error())
			return
		}
	case "refresh":
		if err := a.refreshList(in.Index); err != nil {
			fail(w, 400, err.Error())
			return
		}
	case "mode":
		a.mu.Lock()
		if in.Index < 0 || in.Index >= len(a.st.CustomLists) {
			a.mu.Unlock()
			fail(w, 400, "нет такого списка")
			return
		}
		if in.Mode == "direct" {
			a.st.CustomLists[in.Index].Mode = "direct"
		} else {
			a.st.CustomLists[in.Index].Mode = "proxy"
		}
		a.rev.Add(1)
		st := a.st
		a.mu.Unlock()
		_ = saveSettings(a.dataDir, st)
	case "delete":
		a.mu.Lock()
		if in.Index < 0 || in.Index >= len(a.st.CustomLists) {
			a.mu.Unlock()
			fail(w, 400, "нет такого списка")
			return
		}
		u := a.st.CustomLists[in.Index].URL
		a.st.CustomLists = append(a.st.CustomLists[:in.Index:in.Index], a.st.CustomLists[in.Index+1:]...)
		a.rev.Add(1)
		st := a.st
		a.mu.Unlock()
		_ = os.Remove(listFile(a.dataDir, u))
		_ = saveSettings(a.dataDir, st)
	default:
		fail(w, 400, "неизвестное действие")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "lists": a.settings().CustomLists})
}

// listsLoop keeps connected lists fresh.
func (a *App) listsLoop() {
	time.Sleep(2 * time.Minute)
	for {
		n := len(a.settings().CustomLists)
		for i := 0; i < n; i++ {
			if err := a.refreshList(i); err != nil {
				logf("list %d: %v", i, err)
			}
		}
		select {
		case <-a.quit:
			return
		case <-time.After(12 * time.Hour):
		}
	}
}
