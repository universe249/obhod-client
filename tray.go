package main

type trayHandlers struct {
	Open   func()
	Panel  func() // щелчок по значку: мини-панель (или окно, если панель недоступна или выключена)
	Toggle func()
	Quit   func()
	IsOn   func() bool
	// quick server switch and game mode
	Profiles   func() (names []string, active int)
	Pick       func(i int)
	Game       func() (available, on bool)
	ToggleGame func()
	// «всё через сервер на час»
	TempGlobal       func() (available, on bool)
	ToggleTempGlobal func()
}

// tray icon states
const (
	trayOff = iota
	trayOn
	trayBad
	trayStarting
)
