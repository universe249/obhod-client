package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseMirrors(t *testing.T) {
	m := parseMirrors("https://a.workers.dev/sub/, http://bad.example/sub, https://b.example/x y, https://c.example/sub")
	if len(m) != 2 || m[0] != "https://a.workers.dev/sub" || m[1] != "https://c.example/sub" {
		t.Fatalf("%v", m)
	}
	if mirrorURL("https://hoop.example.ru:8443/sub/tg2", "https://a.dev/sub/") != "https://a.dev/sub/tg2" {
		t.Fatal(mirrorURL("https://hoop.example.ru:8443/sub/tg2", "https://a.dev/sub/"))
	}
	h := http.Header{}
	h.Set("X-Obhod-Mirrors", "https://a.dev/sub")
	if got := parseSubMeta(h, "https://x/sub/n").Mirrors; len(got) != 1 {
		t.Fatal(got)
	}
}

func TestFetchFallsBackToMirror(t *testing.T) {
	mirror := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sub/tg2" {
			w.WriteHeader(404)
			return
		}
		w.Write([]byte("vless://u@h:443#x"))
	}))
	defer mirror.Close()
	http.DefaultTransport.(*http.Transport).TLSClientConfig = mirror.Client().Transport.(*http.Transport).TLSClientConfig
	prev := &SubMeta{Mirrors: []string{mirror.URL + "/sub"}}
	text, meta, err := fetchSubWithMirrors("http://127.0.0.1:1/sub/tg2", prev)
	if err != nil || text == "" || len(meta.Mirrors) != 1 {
		t.Fatalf("%v %q %v", err, text, meta)
	}
	if _, _, err := fetchSubWithMirrors("http://127.0.0.1:1/sub/tg2", nil); err == nil {
		t.Fatal("без зеркал должна быть ошибка")
	}
}
