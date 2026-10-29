package main

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// SubMeta is the information a subscription server sends in its response headers.
type SubMeta struct {
	Title   string   `json:"title,omitempty"`
	Used    int64    `json:"used"`              // upload+download, bytes
	Total   int64    `json:"total"`             // 0 = unlimited / unknown
	Expire  int64    `json:"expire"`            // unix seconds, 0 = none
	Updated int64    `json:"updated"`           // when we last read it
	Count   int      `json:"count"`             // servers in the subscription
	Mirrors []string `json:"mirrors,omitempty"` // запасные адреса подписки (заголовок X-Obhod-Mirrors)
	Ours    bool     `json:"ours,omitempty"`    // подписка нашего сервиса (бот @chaiiniik_bot): красивые карточки серверов
	Notice  string   `json:"notice,omitempty"`  // сервис отказал в серверах (лимит устройств, устаревшая ссылка): что сказать человеку
}

// serviceOK: подключение идёт через подписку нашего сервиса — тогда работают его «удобства»: несколько путей, автовыбор
// сервера, автоподбор способа, схема маршрута. С чужой подпиской или своей ссылкой остаётся базовое подключение.
func serviceOK(st Settings) bool {
	if !st.Server.FromSub || st.SubURL == "" {
		return false
	}
	return st.SubMeta != nil && st.SubMeta.Ours || isOurSub(http.Header{}, st.SubURL)
}

// ourHosts: адреса нашего сервиса. Подписка с них считается нашей, даже если заголовок X-Obhod-Service потерялся.
var ourHosts = []string{"un1v249.ru", "un1v249.su"}

func isOurSub(h http.Header, rawURL string) bool {
	if strings.TrimSpace(h.Get("X-Obhod-Service")) != "" {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, d := range ourHosts {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// parseSubMeta reads Subscription-Userinfo ("upload=1; download=2; total=3; expire=4") and Profile-Title.
func parseSubMeta(h http.Header, rawURL string) *SubMeta {
	m := &SubMeta{}
	for _, part := range strings.Split(h.Get("Subscription-Userinfo"), ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upload", "download":
			m.Used += n
		case "total":
			m.Total = n
		case "expire":
			m.Expire = n
		}
	}
	m.Mirrors = parseMirrors(h.Get("X-Obhod-Mirrors"))
	m.Ours = isOurSub(h, rawURL)
	t := strings.TrimSpace(h.Get("Profile-Title"))
	if rest, ok := strings.CutPrefix(t, "base64:"); ok {
		if b, err := base64.StdEncoding.DecodeString(rest); err == nil {
			t = string(b)
		}
	}
	if m.Title = t; m.Title == "" {
		if u, err := url.Parse(rawURL); err == nil {
			m.Title = u.Hostname()
		}
	}
	return m
}

// parseMirrors keeps at most 5 https addresses from a comma-separated header.
func parseMirrors(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimRight(strings.TrimSpace(p), "/")
		if strings.HasPrefix(p, "https://") && !strings.ContainsAny(p, " \t") && len(p) < 300 {
			out = append(out, p)
		}
		if len(out) == 5 {
			break
		}
	}
	return out
}

// mirrorURL turns a subscription address into the same subscription on a mirror: <mirror>/<last path segment>.
func mirrorURL(subURL, mirror string) string {
	u, err := url.Parse(subURL)
	if err != nil {
		return ""
	}
	seg := u.Path[strings.LastIndex(u.Path, "/")+1:]
	if seg == "" {
		return ""
	}
	return strings.TrimRight(mirror, "/") + "/" + seg
}
