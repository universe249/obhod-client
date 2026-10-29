//go:build !windows

package main

import (
	"io"
	"os"
	"os/exec"
)

// Stubs so the project can be built and tested on Linux.

func registerProtocol(exe string)                {}
func isAdmin() bool                              { return true }
func hide(cmd *exec.Cmd)                         {}
func relaunchAsAdmin() error                     { return nil }
func initJob()                                   {}
func assignToJob(pid int)                        {}
func openAppWindow(url, dataDir string)          {}
func listProcesses() []string                    { return []string{"example.exe"} }
func killAllCore(dataDir string) string          { return "" }
func coreRunning(dataDir string) bool            { return false }
func autostartEnabled() bool                     { return false }
func setAutostart(on bool) error                 { return nil }
func relaunchSelf(exe string, resume bool) error { return nil }

var dpapiProtect func([]byte) ([]byte, error)
var dpapiUnprotect func([]byte) ([]byte, error)

func themeAppWindow(dark bool, bg, text, border uint32) int { return 0 }

func attachConsole() (io.Writer, io.Writer) { return os.Stdout, os.Stderr }

func openExternal(url string) {}
