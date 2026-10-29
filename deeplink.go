package main

import (
	"net/url"
	"strings"
)

// parseDeepLink разбирает ссылку obhod://add?u=<адрес подписки или ссылка на сервер>.
// Возвращает то, что нужно добавить. Сама ссылка ничего не добавляет: пользователь подтверждает в окне программы.
func parseDeepLink(s string) (string, bool) {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || !strings.EqualFold(u.Scheme, "obhod") || !strings.EqualFold(u.Host, "add") {
		return "", false
	}
	v := strings.TrimSpace(u.Query().Get("u"))
	if v == "" || len(v) > 4000 || strings.ContainsAny(v, " \r\n\t") {
		return "", false
	}
	l := strings.ToLower(v)
	for _, p := range []string{"https://", "http://", "vless://", "hysteria2://", "hy2://", "trojan://", "ss://", "vmess://", "tuic://"} {
		if strings.HasPrefix(l, p) {
			return v, true
		}
	}
	return "", false
}
