package main

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSendReport(t *testing.T) {
	var gotCode, gotV string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCode, gotV = r.URL.Query().Get("code"), r.URL.Query().Get("v")
		body, _ = io.ReadAll(r.Body)
		if gotCode != "123456" {
			http.Error(w, "bad", 403)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	a := &App{dataDir: t.TempDir(), core: &Core{}, st: multiSettings()}
	a.st.ReportURL = srv.URL + "/report"
	if err := a.sendReport("999"); err == nil {
		t.Fatal("wrong code must fail")
	}
	if err := a.sendReport(" 123456 "); err != nil {
		t.Fatal(err)
	}
	if gotV == "" {
		t.Fatal("version missing")
	}
	if _, err := zip.NewReader(bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	if err := a.sendReport(""); err == nil {
		t.Fatal("empty code")
	}
}

func TestRedactSecrets(t *testing.T) {
	st := multiSettings()
	st.Server.UUID, st.Server.PublicKey, st.APISecret = "0b9c1d2e-1111-2222-3333-444455556666", "PUBKEYPUBKEYPUBKEY1234", "apisecret123"
	st.SubURL = "https://x.example/sub/secretname"
	in := "start uuid=0b9c1d2e-1111-2222-3333-444455556666 pbk=PUBKEYPUBKEYPUBKEY1234 api=apisecret123 sub=https://x.example/sub/secretname other=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee host=h.example"
	out := redactSecrets(in, st)
	for _, s := range []string{"0b9c1d2e", "PUBKEY", "apisecret", "secretname", "aaaaaaaa"} {
		if strings.Contains(out, s) {
			t.Fatalf("%s не скрыт: %s", s, out)
		}
	}
	if !strings.Contains(out, "host=h.example") {
		t.Fatal("лишнее скрыто: " + out)
	}
}
