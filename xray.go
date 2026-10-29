package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

// xrayConfigBytes builds the Xray-core config: a local SOCKS5 inbound and a VLESS+xhttp outbound.
func xrayConfigBytes(st Settings, dataDir string) ([]byte, error) {
	s := applyHostOverride(st.Server)
	if !needsXray(s) {
		return nil, errors.New("профиль не использует Xray")
	}
	if s.Host == "" || s.Port == 0 || s.UUID == "" {
		return nil, errors.New("не задан сервер")
	}
	sni := s.SNI
	if sni == "" {
		sni = s.Host
	}
	user := m{"id": s.UUID, "encryption": "none"}
	if s.Flow != "" {
		user["flow"] = s.Flow
	}

	path := s.WSPath
	if path == "" {
		path = "/"
	}
	mode := s.XMode
	if mode == "" {
		mode = "auto"
	}
	xh := m{"path": path, "mode": mode}
	if s.WSHost != "" {
		xh["host"] = s.WSHost
	}
	if strings.TrimSpace(s.XExtra) != "" {
		var extra map[string]any
		if err := json.Unmarshal([]byte(s.XExtra), &extra); err != nil {
			return nil, errors.New("поле «extra» должно быть корректным JSON")
		}
		delete(extra, "mode") // mode is a separate setting
		if len(extra) > 0 {
			xh["extra"] = extra
		}
	}

	stream := m{"network": "xhttp", "xhttpSettings": xh}
	fp := s.Fingerprint
	switch s.Security {
	case "reality":
		if s.PublicKey == "" {
			return nil, errors.New("для Reality нужен public key")
		}
		if fp == "" {
			fp = "chrome"
		}
		r := m{"serverName": sni, "fingerprint": fp, "publicKey": s.PublicKey, "shortId": s.ShortID}
		if s.Spx != "" {
			r["spiderX"] = s.Spx
		}
		stream["security"] = "reality"
		stream["realitySettings"] = r
	case "tls":
		t := m{"serverName": sni, "allowInsecure": s.Insecure}
		if fp != "" {
			t["fingerprint"] = fp
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = t
	default:
		stream["security"] = "none"
	}

	cfg := m{
		"log": m{"loglevel": "warning", "error": filepath.Join(dataDir, "xray.log")},
		"inbounds": []m{{
			"tag": "socks-in", "listen": "127.0.0.1", "port": st.XrayPort, "protocol": "socks",
			"settings": m{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
		}},
		"outbounds": []m{{
			"tag": "proxy", "protocol": "vless",
			"settings":       m{"vnext": []m{{"address": s.Host, "port": s.Port, "users": []m{user}}}},
			"streamSettings": stream,
		}},
	}
	return json.MarshalIndent(cfg, "", "  ")
}
