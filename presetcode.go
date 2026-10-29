package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const presetCodePrefix = "OBH1:"

// presetCode упаковывает набор правил в короткую строку, которую можно отправить другу.
func presetCode(p Preset) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.Write(raw)
	zw.Close()
	return presetCodePrefix + base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

func cleanStrs(in []string, max int) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || len(s) > 200 || seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
		if len(out) >= max {
			break
		}
	}
	return out
}

// parsePresetCode проверяет код и возвращает набор. Чужому коду не доверяем: всё чистим.
func parsePresetCode(code string) (Preset, error) {
	code = strings.TrimSpace(code)
	if !strings.HasPrefix(code, presetCodePrefix) {
		return Preset{}, errors.New("это не код набора правил (должен начинаться с OBH1:)")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(code[len(presetCodePrefix):], "="))
	if err != nil {
		return Preset{}, errors.New("код повреждён — скопируй его целиком")
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return Preset{}, errors.New("код повреждён — скопируй его целиком")
	}
	raw, err := io.ReadAll(io.LimitReader(zr, 64<<10))
	if err != nil {
		return Preset{}, errors.New("код повреждён — скопируй его целиком")
	}
	var p Preset
	if json.Unmarshal(raw, &p) != nil {
		return Preset{}, errors.New("код повреждён — скопируй его целиком")
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		p.Name = "Чужой набор"
	}
	if r := []rune(p.Name); len(r) > 40 {
		p.Name = string(r[:40])
	}
	if p.Mode != "global" {
		p.Mode = "smart"
	}
	svc := map[string]bool{}
	for k, v := range p.Services {
		if v && len(k) <= 40 && len(svc) < 100 {
			svc[k] = true
		}
	}
	p.Services = svc
	p.ProxyApps = cleanStrs(p.ProxyApps, 200)
	p.DirectApps = cleanStrs(p.DirectApps, 200)
	return p, nil
}
