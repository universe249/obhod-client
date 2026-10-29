package main

import "testing"

func TestHogRates(t *testing.T) {
	prev := map[string][2]int64{"a": {0, 1000}, "b": {0, 0}}
	cur := []hogConn{
		{ID: "a", Process: "Chrome.exe", Host: "youtube.com", Via: "proxy", Up: 100, Down: 3000},
		{ID: "c", Process: "chrome.exe", Host: "x.com", Via: "direct", Up: 0, Down: 500}, // new: counts from zero
		{ID: "b", Process: "steam.exe", Via: "direct", Up: 0, Down: 100},
		{ID: "d", Process: "sing-box.exe", Via: "direct", Down: 99999},
		{ID: "e", Process: "", Down: 5},
	}
	h := hogRates(prev, cur, 2, isOwnProcess)
	if len(h) != 2 || h[0].Process != "Chrome.exe" {
		t.Fatalf("%+v", h)
	}
	if h[0].Down != 1250 || h[0].Up != 50 || h[0].Via != "mixed" || h[0].Conns != 2 || h[0].Host != "youtube.com" {
		t.Fatalf("%+v", h[0])
	}
	if h[1].Via != "direct" || h[1].Down != 50 {
		t.Fatalf("%+v", h[1])
	}
	// counter reset must not give negative speed
	h = hogRates(map[string][2]int64{"a": {500, 500}}, []hogConn{{ID: "a", Process: "p.exe", Up: 10, Down: 10}}, 1, nil)
	if h[0].Down != 0 || h[0].Up != 0 {
		t.Fatalf("%+v", h[0])
	}
}
