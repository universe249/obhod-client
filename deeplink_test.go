package main

import (
	"net/url"
	"testing"
)

func TestParseDeepLink(t *testing.T) {
	sub := "https://hoop.example.ru:2096/sub/tg1"
	got, ok := parseDeepLink("obhod://add?u=" + url.QueryEscape(sub))
	if !ok || got != sub {
		t.Fatal(got, ok)
	}
	for _, bad := range []string{"obhod://add", "obhod://run?u=https://x", "http://add?u=https://x", "obhod://add?u=file:///c:/x", "obhod://add?u=javascript:alert(1)", "obhod://add?u=" + url.QueryEscape("https://a b")} {
		if _, ok := parseDeepLink(bad); ok {
			t.Fatal("принято лишнее:", bad)
		}
	}
	if _, ok := parseDeepLink("OBHOD://ADD?u=vless%3A%2F%2Fu%40h%3A1%23x"); !ok {
		t.Fatal("регистр")
	}
}
