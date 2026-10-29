//go:build !windows

package main

func startTray(h trayHandlers)      {}
func trayUpdate(state int)          {}
func trayRemove()                   {}
func traySetInfo(string)            {}
func trayNotify(title, text string) {}
