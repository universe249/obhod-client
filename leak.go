package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Echo-IP hosts. The generated config sends the first one through the server and the others direct,
// so the leak test can compare "what the world sees" on both paths.
// extra echo hosts tried through the server if the first one does not answer
var leakProxyHosts = []string{leakProxyHost, "icanhazip.com", "ipv4.icanhazip.com", "ifconfig.me"}

const (
	leakProxyHost  = "checkip.amazonaws.com"
	leakDirectHost = "api.ipify.org"
	leakV6Host     = "api64.ipify.org"
)

type LeakResult struct {
	DirectIP string    `json:"directIp"`
	ProxyIP  string    `json:"proxyIp"`
	V6IP     string    `json:"v6Ip"`
	ServerIP string    `json:"serverIp"`
	Verdicts []Verdict `json:"verdicts"`
}

type Verdict struct {
	OK   bool   `json:"ok"`
	Text string `json:"text"`
}

func fetchIP(ctx context.Context, host string, network string) string {
	d := &net.Dialer{Timeout: 6 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, network, addr) },
	}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/", nil)
	req.Header.Set("User-Agent", "obhod-leaktest")
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

// judgeLeak turns three observed addresses into plain-language verdicts.
func judgeLeak(r LeakResult, ipv6Guard bool) []Verdict {
	var v []Verdict
	switch {
	case r.ProxyIP == "":
		v = append(v, Verdict{false, "Через сервер проверочные сайты не ответили (checkip.amazonaws.com, icanhazip.com, ifconfig.me). Это не обязательно поломка: сами эти сайты могли не открыться с адреса сервера. Если обычные сайты через сервер открываются, всё в порядке."})
	case r.DirectIP != "" && r.ProxyIP == r.DirectIP:
		v = append(v, Verdict{false, "Адрес через сервер совпадает с твоим настоящим (" + r.ProxyIP + ") — трафик идёт мимо туннеля."})
	default:
		txt := "Через сервер сайты видят адрес " + r.ProxyIP
		if r.DirectIP != "" {
			txt += ", обычные сайты — твой " + r.DirectIP
		}
		v = append(v, Verdict{true, txt + "."})
	}
	if r.ServerIP != "" && r.ProxyIP != "" {
		if r.ServerIP == r.ProxyIP {
			v = append(v, Verdict{true, "Выходной адрес совпадает с адресом твоего сервера."})
		} else {
			v = append(v, Verdict{true, "Выходной адрес отличается от адреса сервера (" + r.ServerIP + ") — это нормально, если сервер за NAT или выходит через другой IP."})
		}
	}
	if ip := net.ParseIP(r.V6IP); ip != nil && ip.To4() == nil {
		if ipv6Guard {
			v = append(v, Verdict{false, "Защита IPv6 включена, но IPv6-адрес всё равно виден: " + r.V6IP + ". Перезапусти туннель."})
		} else {
			v = append(v, Verdict{false, "Виден твой IPv6-адрес " + r.V6IP + ": он идёт мимо туннеля. Включи «Защиту от утечки IPv6» на вкладке «Подключение» (раздел «Дополнительно»)."})
		}
	} else {
		v = append(v, Verdict{true, "IPv6-утечки нет."})
	}
	return v
}

func (a *App) handleLeak(w http.ResponseWriter, r *http.Request) {
	if !a.core.Running() {
		fail(w, 400, "сначала включи туннель")
		return
	}
	st := a.settings()
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	type res struct{ k, ip string }
	ch := make(chan res, 3)
	go func() { ch <- res{"direct", fetchIP(ctx, leakDirectHost, "tcp4")} }()
	go func() { ch <- res{"proxy", fetchIPAny(ctx, leakProxyHosts, "tcp4")} }()
	go func() { ch <- res{"v6", fetchIP(ctx, leakV6Host, "tcp6")} }()
	var out LeakResult
	for i := 0; i < 3; i++ {
		x := <-ch
		switch x.k {
		case "direct":
			out.DirectIP = x.ip
		case "proxy":
			out.ProxyIP = x.ip
		case "v6":
			out.V6IP = x.ip
		}
	}
	if ip := net.ParseIP(st.Server.Host); ip != nil {
		out.ServerIP = ip.String()
	} else if ips, err := net.LookupIP(st.Server.Host); err == nil {
		for _, ip := range ips {
			if ip.To4() != nil {
				out.ServerIP = ip.String()
				break
			}
		}
	}
	out.Verdicts = judgeLeak(out, st.BlockIPv6)
	writeJSON(w, 200, out)
}

func fetchIPAny(ctx context.Context, hosts []string, network string) string {
	for _, h := range hosts {
		if ip := fetchIP(ctx, h, network); ip != "" {
			return ip
		}
		if ctx.Err() != nil {
			break
		}
	}
	return ""
}
