package main

import (
	"strings"
	"testing"
)

func TestSteamAlwaysDirectAndTikTokDomains(t *testing.T) {
	st := defaultSettings()
	st.Server = Server{Type: "vless", Host: "1.2.3.4", Port: 443, UUID: "u", Name: "s"}
	st.Services = map[string]bool{"tiktok": true}
	c, err := buildConfig(st, t.TempDir(), map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	var steamDirect, tt bool
	for _, r := range c["route"].(map[string]any)["rules"].([]map[string]any) {
		if p, ok := r["process_name"].([]string); ok && r["outbound"] == "direct" {
			for _, x := range p {
				if x == "steamservice.exe" {
					steamDirect = true
				}
			}
		}
		if d, ok := r["domain_suffix"].([]string); ok && strings.Contains(strings.Join(d, ","), "tiktokcdn-eu.com") && strings.Contains(strings.Join(d, ","), "snssdk.com") {
			tt = true
		}
	}
	if !steamDirect || !tt {
		t.Fatalf("steam=%v tiktok=%v", steamDirect, tt)
	}
}
