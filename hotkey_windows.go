//go:build windows

package main

import (
	"log"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

var (
	procRegisterHotKey   = user32.NewProc("RegisterHotKey")
	procUnregisterHotKey = user32.NewProc("UnregisterHotKey")
	procPeekMessage      = user32.NewProc("PeekMessageW")
)

const (
	wmHotkey    = 0x0312
	pmRemove    = 0x0001
	modNoRepeat = 0x4000
)

type hkMsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	PtX     int32
	PtY     int32
}

type hkRequest struct {
	binds map[string][2]uint32
	fire  func(string)
	reply chan map[string]string
}

var (
	hkOnce sync.Once
	hkReq  = make(chan hkRequest, 4)
)

// hotkeyRegister sends the shortcuts to the thread that owns the registrations (RegisterHotKey is per thread)
// and waits for the result.
func hotkeyRegister(binds map[string][2]uint32, fire func(string)) map[string]string {
	hkOnce.Do(func() { go hkLoop() })
	req := hkRequest{binds: binds, fire: fire, reply: make(chan map[string]string, 1)}
	hkReq <- req
	select {
	case r := <-req.reply:
		return r
	case <-time.After(3 * time.Second):
		return map[string]string{}
	}
}

func hkLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("hotkey thread: %v", r)
		}
	}()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ids := map[uintptr]string{}
	var fire func(string)
	unregisterAll := func() {
		for id := range ids {
			procUnregisterHotKey.Call(0, id)
		}
		ids = map[uintptr]string{}
	}
	var msg hkMsg
	for {
		select {
		case req := <-hkReq:
			unregisterAll()
			fire = req.fire
			res := map[string]string{}
			n := uintptr(1)
			for action, b := range req.binds {
				r, _, _ := procRegisterHotKey.Call(0, n, uintptr(b[0]|modNoRepeat), uintptr(b[1]))
				if r == 0 {
					res[action] = "Это сочетание занято другой программой или Windows"
				} else {
					ids[n] = action
					res[action] = ""
				}
				n++
			}
			req.reply <- res
		default:
		}
		for {
			r, _, _ := procPeekMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, pmRemove)
			if r == 0 {
				break
			}
			if msg.Message == wmHotkey && fire != nil {
				if action, ok := ids[msg.WParam]; ok {
					go fire(action)
				}
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
}
