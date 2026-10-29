package main

import "testing"

func TestDoHServer(t *testing.T) {
	st := defaultSettings()
	st.Server = Server{Type: "vless", Host: "1.2.3.4", Port: 443, UUID: "u", Name: "s"}
	st.Services = map[string]bool{}
	for _, mode := range []string{"", "cloudflare", "google"} {
		st.DNSDoH = mode
		c, err := buildConfig(st, t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		sv := c["dns"].(map[string]any)["servers"].([]map[string]any)[0]
		want := map[string]string{"": "udp", "cloudflare": "https", "google": "https"}[mode]
		if sv["tag"] != "dns-local" || sv["type"] != want {
			t.Fatalf("%q: %v", mode, sv)
		}
	}
}
