//go:build windows

package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"image/color"
	"image/png"
	"log"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var (
	user32                  = syscall.NewLazyDLL("user32.dll")
	procRegisterClassEx     = user32.NewProc("RegisterClassExW")
	procCreateWindowEx      = user32.NewProc("CreateWindowExW")
	procDefWindowProc       = user32.NewProc("DefWindowProcW")
	procGetMessage          = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessage     = user32.NewProc("DispatchMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	procAppendMenu          = user32.NewProc("AppendMenuW")
	procTrackPopupMenu      = user32.NewProc("TrackPopupMenu")
	procDestroyMenu         = user32.NewProc("DestroyMenu")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procPostMessage         = user32.NewProc("PostMessageW")
	procRegisterWindowMsg   = user32.NewProc("RegisterWindowMessageW")
	procCreateIconFromRes   = user32.NewProc("CreateIconFromResourceEx")
	procShellNotify         = shell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandle     = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmTray      = 0x0401 // WM_USER + 1
	wmDestroy   = 0x0002
	nimAdd      = 0
	nimModify   = 1
	nimDelete   = 2
	nifMessage  = 0x1
	nifIcon     = 0x2
	nifTip      = 0x4
	menuOpen    = 1
	menuToggle  = 2
	menuQuit    = 3
	menuGame    = 4
	menuTempAll = 5
	menuProfile = 100 // + index
	mfSeparator = 0x800
	tpmFlags    = 0x0100 | 0x0020 | 0x0002 // RETURNCMD | BOTTOMALIGN | RIGHTBUTTON
)

type guid struct {
	a uint32
	b uint16
	c uint16
	d [8]byte
}

type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         guid
	HBalloonIcon     uintptr
}

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type winMsg struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	PtX     int32
	PtY     int32
}

var (
	trayMu      sync.Mutex
	trayHwnd    uintptr
	trayIcons   [4]uintptr // indexed by tray state
	trayState   int
	trayH       trayHandlers
	trayTaskbar uint32
)

//go:embed assets/tray_on.png
var trayOnPNG []byte

//go:embed assets/tray_off.png
var trayOffPNG []byte

//go:embed assets/tray_bad.png
var trayBadPNG []byte

//go:embed assets/tray_start.png
var trayStartPNG []byte

// makeIcon turns an embedded 32x32 PNG into an HICON.
func makeIcon(pngData []byte) uintptr {
	img, err := png.Decode(bytes.NewReader(pngData))
	if err != nil {
		return 0
	}
	const n = 32
	pix := make([]byte, n*n*4)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			c := color.NRGBAModel.Convert(img.At(img.Bounds().Min.X+x, img.Bounds().Min.Y+y)).(color.NRGBA)
			row := n - 1 - y // bottom-up
			i := (row*n + x) * 4
			pix[i], pix[i+1], pix[i+2], pix[i+3] = c.B, c.G, c.R, c.A
		}
	}
	hdr := make([]byte, 40)
	binary.LittleEndian.PutUint32(hdr[0:], 40)
	binary.LittleEndian.PutUint32(hdr[4:], n)
	binary.LittleEndian.PutUint32(hdr[8:], n*2)
	binary.LittleEndian.PutUint16(hdr[12:], 1)
	binary.LittleEndian.PutUint16(hdr[14:], 32)
	binary.LittleEndian.PutUint32(hdr[20:], uint32(len(pix)))
	data := append(hdr, pix...)
	data = append(data, make([]byte, n*4)...) // AND mask
	h, _, _ := procCreateIconFromRes.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 1, 0x00030000, n, n, 0)
	return h
}

func sqrt(v float64) float64 {
	if v <= 0 {
		return 0
	}
	x := v
	for i := 0; i < 20; i++ {
		x = (x + v/x) / 2
	}
	return x
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

var trayInfo string

// traySetInfo puts a second line (speed, response time) into the tooltip of the tray icon.
func traySetInfo(info string) {
	trayMu.Lock()
	same := trayInfo == info
	trayInfo = info
	trayMu.Unlock()
	if !same {
		nim(nimModify)
	}
}

func trayTip() string {
	switch trayState {
	case trayOn:
		if trayInfo != "" {
			return appName + " — работает\n" + trayInfo
		}
		return appName + " — работает"
	case trayBad:
		return appName + " — нет связи с сервером"
	case trayStarting:
		return appName + " — подключается…"
	}
	return appName + " — выключено"
}

func nim(op uintptr) {
	trayMu.Lock()
	defer trayMu.Unlock()
	if trayHwnd == 0 {
		return
	}
	var d notifyIconData
	d.CbSize = uint32(unsafe.Sizeof(d))
	d.HWnd = trayHwnd
	d.UID = 1
	d.UFlags = nifMessage | nifIcon | nifTip
	d.UCallbackMessage = wmTray
	d.HIcon = trayIcons[trayState]
	tip, _ := syscall.UTF16FromString(trayTip())
	copy(d.SzTip[:127], tip)
	_, _, _ = procShellNotify.Call(op, uintptr(unsafe.Pointer(&d)))
}

// trayNotify shows a balloon notification near the tray icon.
func trayNotify(title, text string) {
	trayMu.Lock()
	defer trayMu.Unlock()
	if trayHwnd == 0 {
		return
	}
	var d notifyIconData
	d.CbSize = uint32(unsafe.Sizeof(d))
	d.HWnd = trayHwnd
	d.UID = 1
	d.UFlags = nifMessage | nifIcon | nifTip | 0x10 // NIF_INFO
	d.UCallbackMessage = wmTray
	d.HIcon = trayIcons[trayState]
	tip, _ := syscall.UTF16FromString(trayTip())
	copy(d.SzTip[:127], tip)
	tt, _ := syscall.UTF16FromString(title)
	copy(d.SzInfoTitle[:63], tt)
	tx, _ := syscall.UTF16FromString(text)
	copy(d.SzInfo[:255], tx)
	d.DwInfoFlags = 1 // NIIF_INFO
	_, _, _ = procShellNotify.Call(nimModify, uintptr(unsafe.Pointer(&d)))
}

func trayUpdate(state int) {
	trayMu.Lock()
	trayState = state
	trayMu.Unlock()
	nim(nimModify)
}

func trayRemove() { nim(nimDelete) }

func showMenu(hwnd uintptr) {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	add := func(id uintptr, text string) {
		p, _ := syscall.UTF16PtrFromString(text)
		_, _, _ = procAppendMenu.Call(menu, 0, id, uintptr(unsafe.Pointer(p)))
	}
	add(menuOpen, "Открыть окно")
	if trayH.IsOn() {
		add(menuToggle, "Выключить туннель")
	} else {
		add(menuToggle, "Включить туннель")
	}
	if trayH.Game != nil {
		if avail, on := trayH.Game(); avail {
			if on {
				add(menuGame, "✔ Игровой режим")
			} else {
				add(menuGame, "Игровой режим")
			}
		}
	}
	if trayH.TempGlobal != nil {
		if avail, on := trayH.TempGlobal(); avail {
			if on {
				add(menuTempAll, "✔ Всё через сервер (на час)")
			} else {
				add(menuTempAll, "Всё через сервер на час")
			}
		}
	}
	if trayH.Profiles != nil {
		if names, active := trayH.Profiles(); len(names) > 1 {
			_, _, _ = procAppendMenu.Call(menu, mfSeparator, 0, 0)
			for i, n := range names {
				if i >= 30 {
					break
				}
				label := n
				if i == active {
					label = "● " + n
				}
				add(uintptr(menuProfile+i), label)
			}
		}
	}
	_, _, _ = procAppendMenu.Call(menu, mfSeparator, 0, 0)
	add(menuQuit, "Выйти")

	var pt struct{ X, Y int32 }
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	_, _, _ = procSetForegroundWindow.Call(hwnd)
	cmd, _, _ := procTrackPopupMenu.Call(menu, tpmFlags, uintptr(pt.X), uintptr(pt.Y), 0, hwnd, 0)
	_, _, _ = procPostMessage.Call(hwnd, 0, 0, 0)
	switch cmd {
	case menuOpen:
		go trayH.Open()
	case menuToggle:
		go trayH.Toggle()
	case menuQuit:
		go trayH.Quit()
	case menuGame:
		if trayH.ToggleGame != nil {
			go trayH.ToggleGame()
		}
	case menuTempAll:
		if trayH.ToggleTempGlobal != nil {
			go trayH.ToggleTempGlobal()
		}
	default:
		if cmd >= menuProfile && trayH.Pick != nil {
			go trayH.Pick(int(cmd) - menuProfile)
		}
	}
}

func trayWndProc(hwnd, msg, wp, lp uintptr) uintptr {
	m := uint32(msg)
	switch {
	case m == wmTray:
		switch uint32(lp) & 0xFFFF {
		case 0x0202: // left button up: мини-панель
			if trayH.Panel != nil {
				go trayH.Panel()
			} else {
				go trayH.Open()
			}
		case 0x0203: // double click: окно программы
			go trayH.Open()
		case 0x0205: // right button up
			showMenu(hwnd)
		}
		return 0
	case trayTaskbar != 0 && m == trayTaskbar: // explorer restarted
		nim(nimAdd)
		return 0
	case m == wmDestroy:
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProc.Call(hwnd, msg, wp, lp)
	return r
}

func startTray(h trayHandlers) {
	trayH = h
	go func() {
		runtime.LockOSThread()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("tray panic: %v", r)
			}
		}()
		trayIcons[trayOff] = makeIcon(trayOffPNG)
		trayIcons[trayOn] = makeIcon(trayOnPNG)
		trayIcons[trayBad] = makeIcon(trayBadPNG)
		trayIcons[trayStarting] = makeIcon(trayStartPNG)
		tb, _ := syscall.UTF16PtrFromString("TaskbarCreated")
		tm, _, _ := procRegisterWindowMsg.Call(uintptr(unsafe.Pointer(tb)))
		trayTaskbar = uint32(tm)

		inst, _, _ := procGetModuleHandle.Call(0)
		cls, _ := syscall.UTF16PtrFromString("SingUITrayWnd")
		var wc wndClassEx
		wc.CbSize = uint32(unsafe.Sizeof(wc))
		wc.LpfnWndProc = syscall.NewCallback(trayWndProc)
		wc.HInstance = inst
		wc.LpszClassName = cls
		if a, _, e := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); a == 0 {
			log.Printf("tray: RegisterClassEx: %v", e)
			return
		}
		title, _ := syscall.UTF16PtrFromString(appName)
		hwnd, _, e := procCreateWindowEx.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(title)), 0,
			0, 0, 0, 0, 0, 0, inst, 0)
		if hwnd == 0 {
			log.Printf("tray: CreateWindowEx: %v", e)
			return
		}
		trayMu.Lock()
		trayHwnd = hwnd
		trayMu.Unlock()
		nim(nimAdd)

		var msg winMsg
		for {
			r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
			if r == 0 || int32(r) == -1 {
				return
			}
			_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			_, _, _ = procDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
		}
	}()
}

// compile-time checks that the structs match the Win32 x64 layouts
var (
	_ [976]byte = [unsafe.Sizeof(notifyIconData{})]byte{}
	_ [80]byte  = [unsafe.Sizeof(wndClassEx{})]byte{}
	_ [48]byte  = [unsafe.Sizeof(winMsg{})]byte{}
)
