package main

import (
	"log"
	"sync"
	"time"
)

// Health is the last known state of the connection through the server.
type Health struct {
	mu     sync.Mutex
	State  string // unknown | ok | bad
	PingMs int
	Fails  int
}

func (h *Health) Get() (string, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.State, h.PingMs
}

func (h *Health) set(state string, ms, fails int) {
	h.mu.Lock()
	h.State, h.PingMs, h.Fails = state, ms, fails
	h.mu.Unlock()
}

// slowWindow keeps the last ping results; a failure is stored as -1.
type slowWindow struct{ s []int }

const slowSamples = 6

func (w *slowWindow) add(ms int) {
	w.s = append(w.s, ms)
	if len(w.s) > slowSamples {
		w.s = w.s[len(w.s)-slowSamples:]
	}
}

func (w *slowWindow) reset() { w.s = nil }

// degraded: a full window where at least 4 pings failed or were slower than limit ms.
func (w *slowWindow) degraded(limit int) bool {
	if len(w.s) < slowSamples {
		return false
	}
	bad := 0
	for _, v := range w.s {
		if v < 0 || v > limit {
			bad++
		}
	}
	return bad >= 4
}

const slowLimitMs = 1500
const slowCooldown = 15 * time.Minute

func (a *App) notify(title, text string) {
	a.event(eventKind(text), text)
	if a.settings().Notify {
		trayNotify(title, text)
	}
}

func (a *App) setWant(v bool) {
	a.mu.Lock()
	a.wantOn = v
	a.mu.Unlock()
}

func (a *App) wanted() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.wantOn
}

// pingProxy measures a request through the proxy outbound.
func (a *App) pingProxy(st Settings) (int, bool) {
	for _, u := range []string{"http://www.gstatic.com/generate_204", "http://cp.cloudflare.com/generate_204"} {
		if ms, err := clashDelay(st, "proxy", u); err == nil {
			return ms, true
		}
	}
	return 0, false
}

// allowRestart allows at most 3 automatic restarts per 10 minutes and records this one.
func (a *App) allowRestart() bool {
	a.restartMu.Lock()
	defer a.restartMu.Unlock()
	now := time.Now()
	var keep []time.Time
	for _, t := range a.restarts {
		if now.Sub(t) < 10*time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) >= 3 {
		a.restarts = keep
		return false
	}
	a.restarts = append(keep, now)
	return true
}

// shouldTellGiveUp limits the "cannot restore" notice to once per 30 minutes.
func (a *App) shouldTellGiveUp() bool {
	a.restartMu.Lock()
	defer a.restartMu.Unlock()
	if time.Since(a.lastGiveUp) < 30*time.Minute {
		return false
	}
	a.lastGiveUp = time.Now()
	return true
}

func (a *App) autoRestart(reason string) {
	if !a.allowRestart() {
		// 3 restarts per 10 minutes is the pace limit, not a verdict: the tunnel stays wanted, and when the window
		// frees up the watchdog tries again (after a long outage the connection must come back by itself)
		if a.shouldTellGiveUp() {
			a.notify(appName, "Туннель пока не удаётся восстановить. Программа продолжит попытки сама, нажми «Найти проблему» в «Помощи».")
		}
		return
	}
	log.Printf("watchdog: restart (%s)", reason)
	a.notify(appName, reason+" Перезапускаю туннель…")
	a.core.Stop()
	if err := startedOK(a.core.Start(a.settings())); err != nil {
		log.Printf("watchdog: start failed: %v", err)
		a.notify(appName, "Не удалось перезапустить: "+err.Error())
	}
}

func (a *App) watchdog() {
	prevState := "unknown"
	fails := 0
	var win slowWindow
	var lastSlow, lastBlind time.Time
	var firstFail time.Time // когда пропала связь (первая неудачная проверка подряд)
	for {
		select {
		case <-a.quit:
			return
		case <-time.After(10 * time.Second):
		}
		st := a.settings()
		running, _, up, _, _ := a.core.Info()

		if !running {
			a.health.set("unknown", 0, 0)
			a.hist.TunnelStopped(time.Now())
			prevState, fails = "unknown", 0
			win.reset()
			if st.Watchdog && a.wanted() && st.Server.Host != "" {
				a.autoRestart("Туннель остановился.")
			}
			continue
		}
		if up < 12*time.Second {
			continue
		}
		var cn struct{}
		if clashGet(st, "/connections", &cn) != nil {
			// process is alive but the control API does not answer
			fails++
			if st.Watchdog && fails >= 3 {
				fails = 0
				a.autoRestart("Туннель завис.")
			}
			continue
		}
		ms, ok := a.pingProxy(st)
		a.srv.record(a.net.get(), bucketOf(time.Now()), srvID(st.Server), ok, ms)
		if d := a.hist.Record(time.Now(), ok, ms); d >= 5*time.Minute && !a.hist.notified {
			a.hist.notified = true
			a.notify(appName, "Нет связи с сервером уже "+fmtDur(d)+".")
		}
		if ok {
			if prevState == "bad" {
				msg := "Связь с сервером вернулась."
				if !firstFail.IsZero() {
					msg = "Связь с сервером вернулась. Её не было " + fmtDur(time.Since(firstFail)) + "."
				}
				a.notify(appName, msg)
			}
			firstFail = time.Time{}
			fails, prevState = 0, "ok"
			netHint.set(netVerdict{}, false)
			a.health.set("ok", ms, 0)
			win.add(ms)
			if st.Watchdog && ((st.Failover && st.SlowSwitch) || st.AutoTune) && win.degraded(slowLimitMs) && time.Since(lastSlow) > slowCooldown {
				if msg, ok := a.autoTune("Связь нестабильная"); ok {
					lastSlow = time.Now()
					win.reset()
					a.autoRestart(msg)
				} else if name, ok := a.failoverSlow(); ok {
					lastSlow = time.Now()
					win.reset()
					a.autoRestart("Связь нестабильная, переключаюсь на «" + name + "».")
				}
			}
			continue
		}
		win.add(-1)
		if fails == 0 && firstFail.IsZero() {
			firstFail = time.Now()
		}
		fails++
		a.health.set(map[bool]string{true: "bad", false: prevState}[fails >= 3], 0, fails)
		if fails == 3 {
			prevState = "bad"
			a.notify(appName, "Нет связи с сервером.")
			go probeNetwork(st)
		}
		if st.Watchdog && fails >= 6 {
			fails = 0
			prevState = "unknown"
			if msg, ok := a.autoTune("Сервер не отвечает"); ok {
				a.autoRestart(msg)
			} else if name, ok := a.failoverNext(); ok {
				a.autoRestart("Сервер не отвечает, переключаюсь на «" + name + "».")
			} else if time.Since(lastBlind) >= 5*time.Minute {
				// nothing to switch to: one restart can help (stuck connections), but restarting every minute only
				// breaks the user's connections while the cause is outside the tunnel
				lastBlind = time.Now()
				a.autoRestart("Нет связи с сервером.")
			}
		}
	}
}
