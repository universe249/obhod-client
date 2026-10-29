package main

import (
	"os"
	"testing"
)

// SINGUI_DUMP=/dir go test -run TestDump writes sample configs for `sing-box check`.
func TestDump(t *testing.T) {
	dir := os.Getenv("SINGUI_DUMP")
	if dir == "" {
		t.Skip()
	}
	st := multiSettings()
	st.Fragment = true
	st.AutoBest = true
	st.Services["gemini"] = true
	st.Services["claude"] = true
	st.GroupServers = map[string]string{"ИИ и нейросети": "US"}
	b, err := configBytes(st, dir, map[string]bool{"geosite-facebook": true})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dir+"/full.json", b, 0o644)
}
