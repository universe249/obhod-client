package main

import (
	"strings"
	"sync"
	"time"
)

// Event is one line of the "what happened" feed on the main screen.
type Event struct {
	T    int64  `json:"t"`    // unix seconds
	Kind string `json:"kind"` // info | ok | warn | bad
	Text string `json:"text"`
}

const eventsKeep = 40

type eventLog struct {
	mu   sync.Mutex
	list []Event
}

// add records an event; an identical text within a minute only refreshes the time.
func (e *eventLog) add(kind, text string, now time.Time) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if n := len(e.list); n > 0 && e.list[n-1].Text == text && now.Unix()-e.list[n-1].T < 60 {
		e.list[n-1].T = now.Unix()
		return
	}
	e.list = append(e.list, Event{T: now.Unix(), Kind: kind, Text: text})
	if len(e.list) > eventsKeep {
		e.list = e.list[len(e.list)-eventsKeep:]
	}
}

// recent returns up to n events, newest first.
func (e *eventLog) recent(n int) []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Event
	for i := len(e.list) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, e.list[i])
	}
	return out
}

// eventKind guesses the colour of a notification from its wording.
func eventKind(text string) string {
	t := strings.ToLower(text)
	switch {
	case strings.Contains(t, "восстановлен"), strings.Contains(t, "добавлено"), strings.Contains(t, "включён"):
		return "ok"
	case strings.Contains(t, "нет связи"), strings.Contains(t, "не отвечает"), strings.Contains(t, "остановил"),
		strings.Contains(t, "завис"), strings.Contains(t, "не удалось"), strings.Contains(t, "закончил"):
		return "bad"
	case strings.Contains(t, "переключа"), strings.Contains(t, "перезапуска"), strings.Contains(t, "нестабиль"),
		strings.Contains(t, "заканчива"), strings.Contains(t, "трафика"):
		return "warn"
	}
	return "info"
}

func (a *App) event(kind, text string) {
	a.events.add(kind, text, time.Now())
	if kind == "bad" || kind == "warn" {
		a.tele(kind, text)
	}
}
