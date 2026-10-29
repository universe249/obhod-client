package main

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

func truthy(v string) bool {
	v = strings.ToLower(v)
	return v == "1" || v == "true" || v == "yes"
}

// parseLink understands hysteria2:// (hy2://) and vless:// share links.
func parseLink(link string) (Server, error) {
	link = strings.TrimSpace(link)
	if strings.HasPrefix(strings.ToLower(link), "ss://") {
		return parseSS(link)
	}
	link, multiPort := splitHy2MultiPort(link)
	u, err := url.Parse(link)
	if err != nil {
		return Server{}, errors.New("не удалось разобрать ссылку")
	}
	q := u.Query()
	port := 443
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Server{}, errors.New("неверный порт в ссылке")
		}
		port = n
	}
	host := u.Hostname()
	if host == "" {
		return Server{}, errors.New("в ссылке нет адреса сервера")
	}
	srv := Server{Name: u.Fragment, Host: host, Port: port, SNI: q.Get("sni")}

	switch strings.ToLower(u.Scheme) {
	case "hysteria2", "hy2":
		srv.Type = "hysteria2"
		pw := u.User.Username()
		if p, ok := u.User.Password(); ok {
			pw += ":" + p
		}
		srv.Password = pw
		if q.Get("obfs") == "salamander" {
			srv.ObfsPassword = q.Get("obfs-password")
		}
		srv.Insecure = truthy(q.Get("insecure"))
		srv.HopPorts = q.Get("mport")
		if srv.HopPorts == "" {
			srv.HopPorts = multiPort
		}
		if srv.Name == "" {
			srv.Name = "Hysteria2"
		}
	case "trojan":
		srv.Type = "trojan"
		srv.Password = u.User.Username()
		if srv.Password == "" {
			return Server{}, errors.New("в ссылке Trojan нет пароля")
		}
		srv.Security = q.Get("security")
		if srv.Security == "" {
			srv.Security = "tls"
		}
		srv.Fingerprint = q.Get("fp")
		srv.Insecure = truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure"))
		srv.Network = q.Get("type")
		switch srv.Network {
		case "", "tcp":
			srv.Network = "tcp"
			if h := q.Get("headerType"); h != "" && h != "none" {
				return Server{}, errors.New("маскировка TCP под «" + h + "» не поддерживается: в s-ui выбери для входящего «Нет» в настройке заголовка")
			}
		case "ws":
			srv.WSPath = q.Get("path")
			srv.WSHost = q.Get("host")
		default:
			return Server{}, errors.New("транспорт «" + srv.Network + "» для Trojan не поддерживается (только tcp и ws)")
		}
		if srv.Name == "" {
			srv.Name = "Trojan"
		}
	case "vless":
		srv.Type = "vless"
		srv.UUID = u.User.Username()
		if srv.UUID == "" {
			return Server{}, errors.New("в ссылке VLESS нет UUID")
		}
		srv.Flow = q.Get("flow")
		srv.Security = q.Get("security")
		if srv.Security == "" {
			srv.Security = "none"
		}
		srv.Fingerprint = q.Get("fp")
		srv.PublicKey = q.Get("pbk")
		srv.ShortID = q.Get("sid")
		srv.Insecure = truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure"))
		srv.Spx = q.Get("spx")
		srv.Network = q.Get("type")
		switch srv.Network {
		case "", "tcp":
			srv.Network = "tcp"
			if h := q.Get("headerType"); h != "" && h != "none" {
				return Server{}, errors.New("маскировка TCP под «" + h + "» не поддерживается: в s-ui выбери для входящего «Нет» в настройке заголовка")
			}
		case "ws":
			srv.WSPath = q.Get("path")
			srv.WSHost = q.Get("host")
		case "xhttp":
			srv.WSPath = q.Get("path")
			srv.WSHost = q.Get("host")
			srv.XMode = q.Get("mode")
			srv.XExtra = q.Get("extra")
			if srv.XExtra == "" && q.Get("x_padding_bytes") != "" {
				srv.XExtra = `{"xPaddingBytes":"` + q.Get("x_padding_bytes") + `"}`
			}
		default:
			return Server{}, errors.New("транспорт «" + srv.Network + "» не поддерживается (только tcp, ws и xhttp)")
		}
		if srv.Name == "" {
			srv.Name = "VLESS"
		}
	default:
		return Server{}, errors.New("не удалось разобрать ссылку: поддерживаются hysteria2://, vless://, trojan:// и ss://")
	}
	return srv, nil
}

func b64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(strings.TrimRight(s, "=")); err == nil {
			return b, nil
		}
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("не base64")
}

// parseSS reads ss://BASE64(method:password)@host:port#name (SIP002),
// ss://method:password@host:port#name and the legacy ss://BASE64(method:password@host:port)#name.
func parseSS(link string) (Server, error) {
	rest := link[len("ss://"):]
	name := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		name, _ = url.QueryUnescape(rest[i+1:])
		rest = rest[:i]
	}
	if i := strings.Index(rest, "?"); i >= 0 { // plugin parameters are not supported
		if strings.Contains(rest[i:], "plugin=") {
			return Server{}, errors.New("Shadowsocks с плагином не поддерживается")
		}
		rest = rest[:i]
	}
	var userinfo, hostport string
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		userinfo, hostport = rest[:i], rest[i+1:]
		if !strings.Contains(userinfo, ":") {
			b, err := b64(userinfo)
			if err != nil {
				return Server{}, errors.New("не удалось разобрать ссылку Shadowsocks")
			}
			userinfo = string(b)
		} else if dec, err := url.QueryUnescape(userinfo); err == nil {
			userinfo = dec
		}
	} else {
		b, err := b64(rest)
		if err != nil {
			return Server{}, errors.New("не удалось разобрать ссылку Shadowsocks")
		}
		s := string(b)
		i := strings.LastIndex(s, "@")
		if i < 0 {
			return Server{}, errors.New("не удалось разобрать ссылку Shadowsocks")
		}
		userinfo, hostport = s[:i], s[i+1:]
	}
	method, pass, ok := strings.Cut(userinfo, ":")
	if !ok || method == "" {
		return Server{}, errors.New("в ссылке Shadowsocks нет метода шифрования")
	}
	h, p, ok := strings.Cut(strings.TrimSuffix(hostport, "/"), ":")
	if strings.HasPrefix(hostport, "[") {
		if j := strings.LastIndex(hostport, "]:"); j > 0 {
			h, p, ok = strings.Trim(hostport[:j+1], "[]"), hostport[j+2:], true
		}
	}
	port, err := strconv.Atoi(p)
	if !ok || err != nil || port < 1 || port > 65535 || h == "" {
		return Server{}, errors.New("неверный адрес в ссылке Shadowsocks")
	}
	if name == "" {
		name = "Shadowsocks"
	}
	return Server{Name: name, Type: "shadowsocks", Host: h, Port: port, Method: method, Password: pass}, nil
}

// splitHy2MultiPort handles the official Hysteria2 form host:443,20000-30000 (several ports in the address),
// which url.Parse rejects: the first port stays the main one, the whole list becomes the hopping ports.
func splitHy2MultiPort(link string) (string, string) {
	low := strings.ToLower(link)
	if !strings.HasPrefix(low, "hysteria2://") && !strings.HasPrefix(low, "hy2://") {
		return link, ""
	}
	start := strings.Index(link, "://") + 3
	end := len(link)
	if i := strings.IndexAny(link[start:], "/?#"); i >= 0 {
		end = start + i
	}
	auth := link[start:end]
	hostStart := strings.LastIndex(auth, "@") + 1
	colon := strings.LastIndex(auth, ":")
	if colon < hostStart || colon < strings.LastIndex(auth, "]") {
		return link, ""
	}
	ports := auth[colon+1:]
	if !strings.ContainsAny(ports, ",-") || len(normHop(ports)) == 0 {
		return link, ""
	}
	first := normHop(ports)[0]
	if i := strings.Index(first, ":"); i >= 0 {
		first = first[:i]
	}
	return link[:start] + auth[:colon+1] + first + link[end:], ports
}
