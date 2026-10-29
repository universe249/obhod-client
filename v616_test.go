package main

import (
	"strings"
	"testing"
	"time"
)

func TestPathNotifier(t *testing.T) {
	var p pathNotifier
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	step := func(cur string, s int) string { return p.step(cur, "vlesska", "через «Питер»", at(s)) }
	// старт на основном пути: молчим
	for s := 0; s <= 40; s += 5 {
		if m := step("vlesska", s); m != "" {
			t.Fatalf("start: %q", m)
		}
	}
	// короткий скачок на Питер (15 с) — молчим
	step("vlesska (через Питер)", 45)
	step("vlesska (через Питер)", 55)
	if m := step("vlesska", 60); m != "" {
		t.Fatalf("blip: %q", m)
	}
	step("vlesska", 95)
	// настоящий уход на Питер: одно уведомление после 30 с
	got := ""
	for s := 100; s <= 200; s += 5 {
		if m := step("vlesska (через Питер)", s); m != "" {
			if got != "" {
				t.Fatal("twice")
			}
			got = m
		}
	}
	if !strings.Contains(got, "Питер") {
		t.Fatalf("switch: %q", got)
	}
	// возвращение — сообщаем
	back := ""
	for s := 205; s <= 260; s += 5 {
		if m := step("vlesska", s); m != "" {
			back = m
		}
	}
	if !strings.Contains(back, "основному") {
		t.Fatalf("back: %q", back)
	}
	// снова уход через 5 минут — не чаще раза в 15 минут, и о возвращении тогда тоже молчим
	for s := 500; s <= 600; s += 5 {
		if m := step("vlesska (через Стокгольм)", s); m != "" {
			t.Fatalf("throttle: %q", m)
		}
	}
	for s := 605; s <= 700; s += 5 {
		if m := step("vlesska", s); m != "" {
			t.Fatalf("silent back: %q", m)
		}
	}
}

func TestTempGlobal(t *testing.T) {
	st := multiPathSettings()
	st.Mode = "smart"
	now := time.Now()
	final := func(st Settings) string {
		cfg, err := buildConfig(st, t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		return cfg["route"].(m)["final"].(string)
	}
	if final(st) != "direct" || tempGlobalLeft(st, now) != 0 {
		t.Fatal("smart")
	}
	st.GlobalUntil = now.Add(time.Hour).Unix()
	if final(st) != "proxy" || tempGlobalLeft(st, now) < 3590 {
		t.Fatal("temp global")
	}
	st.GlobalUntil = now.Add(-time.Second).Unix() // время вышло
	if final(st) != "direct" || tempGlobalLeft(st, now) != 0 {
		t.Fatal("expired")
	}
	st.Mode, st.GlobalUntil = "global", now.Add(time.Hour).Unix()
	if tempGlobalLeft(st, now) != 0 { // режим и так «всё»: таймер не показываем
		t.Fatal("global")
	}
}

func TestMiniPlace(t *testing.T) {
	work := wvRect{0, 0, 1920, 1040} // панель задач снизу
	x, y := miniPlace(1800, 1060, 340, 470, work, 10)
	if x != 1920-10-340 || y != 1040-10-470 {
		t.Fatalf("bottom: %d %d", x, y)
	}
	top := wvRect{0, 40, 1920, 1080} // панель задач сверху
	if x, y = miniPlace(1800, 20, 340, 470, top, 10); y != 50 || x+340 > 1910 {
		t.Fatalf("top: %d %d", x, y)
	}
	left := wvRect{60, 0, 1920, 1080} // панель задач слева
	if x, _ = miniPlace(30, 900, 340, 470, left, 10); x != 70 {
		t.Fatalf("left: %d", x)
	}
}
