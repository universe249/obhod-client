package main

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// serverLink — обратная операция к parseLink: собирает ссылку для переноса на другое устройство.
func serverLink(s Server) string {
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	hp := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	frag := "#" + url.PathEscape(s.Name)
	enc := func() string {
		if len(q) == 0 {
			return ""
		}
		return "?" + q.Encode()
	}
	switch s.Type {
	case "hysteria2":
		set("sni", s.SNI)
		if s.ObfsPassword != "" {
			q.Set("obfs", "salamander")
			q.Set("obfs-password", s.ObfsPassword)
		}
		if s.Insecure {
			q.Set("insecure", "1")
		}
		set("mport", s.HopPorts)
		return "hysteria2://" + url.PathEscape(s.Password) + "@" + hp + "/" + enc() + frag
	case "trojan":
		set("sni", s.SNI)
		set("security", s.Security)
		set("fp", s.Fingerprint)
		if s.Insecure {
			q.Set("allowInsecure", "1")
		}
		if s.Network == "ws" {
			q.Set("type", "ws")
			set("path", s.WSPath)
			set("host", s.WSHost)
		}
		return "trojan://" + url.PathEscape(s.Password) + "@" + hp + enc() + frag
	case "vless":
		sec := s.Security
		if sec == "" {
			sec = "none"
		}
		set("sni", s.SNI)
		set("flow", s.Flow)
		q.Set("security", sec)
		set("fp", s.Fingerprint)
		set("pbk", s.PublicKey)
		set("sid", s.ShortID)
		set("spx", s.Spx)
		if s.Insecure {
			q.Set("allowInsecure", "1")
		}
		switch s.Network {
		case "ws":
			q.Set("type", "ws")
			set("path", s.WSPath)
			set("host", s.WSHost)
		case "xhttp":
			q.Set("type", "xhttp")
			set("path", s.WSPath)
			set("host", s.WSHost)
			set("mode", s.XMode)
			set("extra", s.XExtra)
		}
		return "vless://" + url.PathEscape(s.UUID) + "@" + hp + enc() + frag
	case "shadowsocks":
		ui := strings.TrimRight(b64enc(s.Method+":"+s.Password), "=")
		return "ss://" + ui + "@" + hp + frag
	}
	return ""
}

func b64enc(s string) string {
	const al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := []byte(s)
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var v uint
		n := 0
		for j := 0; j < 3; j++ {
			v <<= 8
			if i+j < len(b) {
				v |= uint(b[i+j])
				n++
			}
		}
		for j := 0; j <= n; j++ {
			sb.WriteByte(al[v>>(18-6*uint(j))&63])
		}
	}
	return sb.String()
}
