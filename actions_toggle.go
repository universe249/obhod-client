package main

import (
	"errors"
	"log"
)

// toggleTunnel switches the tunnel on or off (tray menu and hotkey use it).
func (a *App) toggleTunnel(announce bool) {
	if a.core.Running() {
		a.setWant(false)
		a.core.Stop()
		if announce {
			a.notify(appName, "Обход выключен.")
		}
		return
	}
	a.setWant(true)
	if err := a.core.Start(a.settings()); err != nil && !errors.Is(err, errAlreadyRunning) {
		log.Printf("toggle start: %v", err)
		a.setWant(false)
		a.notify(appName, "Не удалось включить: "+err.Error())
		return
	}
	if announce {
		a.notify(appName, "Обход включён.")
	}
}

// toggleGame switches game mode and tells the user.
func (a *App) toggleGame() {
	on := !a.settings().GameMode
	if err := a.setGame(on); err != nil {
		a.notify(appName, err.Error())
		return
	}
	if on {
		a.notify(appName, "Игровой режим включён: игры идут напрямую.")
	} else {
		a.notify(appName, "Игровой режим выключен.")
	}
}
