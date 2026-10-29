package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseSubMeta(t *testing.T) {
	h := http.Header{}
	h.Set("Subscription-Userinfo", "upload=100; download=200; total=1000; expire=1893456000")
	h.Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("Мой VPN")))
	m := parseSubMeta(h, "https://x.example/sub/a")
	if m.Used != 300 || m.Total != 1000 || m.Expire != 1893456000 || m.Title != "Мой VPN" {
		t.Fatalf("%+v", m)
	}
	m = parseSubMeta(http.Header{}, "https://x.example/sub/a")
	if m.Title != "x.example" || m.Total != 0 {
		t.Fatalf("%+v", m)
	}
}

func TestSmartAddAndSubscriptionBlock(t *testing.T) {
	link1 := "vless://11111111-1111-1111-1111-111111111111@a.example:8443?security=tls&type=tcp&sni=a.example#A"
	link2 := "vless://22222222-2222-2222-2222-222222222222@b.example:8443?security=tls&type=tcp&sni=b.example#B"
	body := base64.StdEncoding.EncodeToString([]byte(link1 + "\n" + link2))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=1; download=2; total=100; expire=1893456000")
		w.Write([]byte(body))
	}))
	defer srv.Close()
	a := &App{dataDir: t.TempDir(), core: &Core{}, st: Settings{}}
	call := func(in map[string]any) map[string]any {
		b, _ := json.Marshal(in)
		rec := httptest.NewRecorder()
		a.handleProfiles(rec, httptest.NewRequest("POST", "/api/profiles", bytes.NewReader(b)))
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != 200 {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		return out
	}
	// an http address is a subscription
	call(map[string]any{"action": "smart", "text": srv.URL + "/sub/x"})
	if len(a.st.Profiles) != 2 || a.st.SubURL == "" || a.st.SubMeta == nil || a.st.SubMeta.Total != 100 || a.st.SubMeta.Count != 2 || a.st.SubMeta.Used != 3 {
		t.Fatalf("%+v %+v", a.st.Profiles, a.st.SubMeta)
	}
	// a server link is just added (no subscription change)
	link3 := strings.Replace(link1, "a.example", "c.example", 1)
	call(map[string]any{"action": "smart", "text": link3})
	if len(a.st.Profiles) != 3 {
		t.Fatalf("profiles %d", len(a.st.Profiles))
	}
	// several links at once
	call(map[string]any{"action": "smart", "text": strings.Replace(link1, "a.example", "d.example", 1) + "\n" + strings.Replace(link1, "a.example", "e.example", 1)})
	if len(a.st.Profiles) != 5 {
		t.Fatalf("profiles %d", len(a.st.Profiles))
	}
	// refresh updates the stamp, unsub keeps the servers
	a.st.SubMeta.Updated = 0
	call(map[string]any{"action": "refresh"})
	if a.st.SubMeta.Updated == 0 {
		t.Fatal("not refreshed")
	}
	call(map[string]any{"action": "unsub"})
	if a.st.SubURL != "" || a.st.SubMeta != nil || len(a.st.Profiles) != 5 {
		t.Fatalf("%+v", a.st)
	}
}
