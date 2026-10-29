package main

import (
	"strings"
	"time"
)

const autoGameOffAfter = 90 * time.Second

// autoGameAction decides what the game watcher should do: "on", "off" or "".
// running: a game from the list is running now. autoOn: game mode was switched on by the watcher.
func autoGameAction(running, gameMode, autoOn bool, idleSince, now time.Time) string {
	switch {
	case running && !gameMode:
		return "on"
	case !running && gameMode && autoOn && !idleSince.IsZero() && now.Sub(idleSince) >= autoGameOffAfter:
		return "off"
	}
	return ""
}

func anyRunning(procs, games []string) bool {
	set := map[string]bool{}
	for _, p := range procs {
		set[strings.ToLower(p)] = true
	}
	for _, g := range games {
		if set[strings.ToLower(normApp(g))] {
			return true
		}
	}
	return false
}

// autoGameLoop turns game mode on when a game from the list starts and off after it has been closed.
func (a *App) autoGameLoop() {
	var idleSince time.Time
	autoOn := false
	held := false // the user switched game mode off while the game runs: do not force it back on until it closes
	prevGame := false
	for {
		select {
		case <-a.quit:
			return
		case <-time.After(8 * time.Second):
		}
		st := a.settings()
		if !st.AutoGame || len(st.GameApps) == 0 || !a.core.Running() {
			idleSince = time.Time{}
			continue
		}
		running := anyRunning(listProcesses(), st.GameApps)
		if !st.GameMode {
			if prevGame && running {
				held = true
			}
			autoOn = false // switched off by hand: nothing for us to switch off later
		}
		prevGame = st.GameMode
		if !running {
			held = false
		}
		if held {
			continue
		}
		now := time.Now()
		if running {
			idleSince = time.Time{}
		} else if idleSince.IsZero() {
			idleSince = now
		}
		switch autoGameAction(running, st.GameMode, autoOn, idleSince, now) {
		case "on":
			if err := a.setGame(true); err == nil {
				autoOn, prevGame = true, true
				a.notify(appName, "Запущена игра: игровой режим включён, игры идут напрямую.")
			}
		case "off":
			if err := a.setGame(false); err == nil {
				autoOn, prevGame = false, false
				a.notify(appName, "Игра закрыта: игровой режим выключен.")
			}
		}
	}
}
