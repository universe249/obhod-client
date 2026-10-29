//go:build windows

package main

import (
	"log"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"github.com/jchv/go-webview2/pkg/edge"
	"github.com/jchv/go-webview2/webviewloader"
)

// Мини-панель у значка в трее: маленькое окно без рамки (как у звука или сети в Windows) с кнопкой включения,
// путём, пингом и скоростью. Прячется, когда щёлкнешь мимо неё. Окно создаётся при первом щелчке и живёт,
// пока им пользуются; через 10 минут в скрытом виде закрывается, чтобы не держать память.

const (
	miniW, miniH = 340, 530 // в точках при масштабе 100 %
	miniIdle     = 10 * time.Minute
)

var mini struct {
	sync.Mutex
	open     bool
	ready    bool
	hwnd     uintptr
	w        webview2.WebView
	hiddenAt time.Time // когда спряталась, потеряв фокус (щелчок по значку в этот момент не должен открыть её снова)
	gen      int       // номер показа: таймер закрытия срабатывает, только если с тех пор панель не открывали
}

var (
	miniU32          = syscall.NewLazyDLL("user32.dll")
	miniShowWindow   = miniU32.NewProc("ShowWindow")
	miniSetWindowPos = miniU32.NewProc("SetWindowPos")
	miniSetFg        = miniU32.NewProc("SetForegroundWindow")
	miniCursorPos    = miniU32.NewProc("GetCursorPos")
	miniMonFromPt    = miniU32.NewProc("MonitorFromPoint")
	miniMonInfo      = miniU32.NewProc("GetMonitorInfoW")
	miniDpiForWindow = miniU32.NewProc("GetDpiForWindow")
	miniIsVisible    = miniU32.NewProc("IsWindowVisible")
)

type miniMonitorInfo struct {
	CbSize    uint32
	RcMonitor wvRect
	RcWork    wvRect
	DwFlags   uint32
}

// toggleMiniPanel показывает панель у курсора или прячет её. false — панель недоступна (нет WebView2):
// тогда вызывающий открывает обычное окно.
func toggleMiniPanel(url, dataDir string, openMain func()) bool {
	mini.Lock()
	if mini.open {
		h, ready := mini.hwnd, mini.ready
		justHidden := time.Since(mini.hiddenAt) < 400*time.Millisecond
		mini.Unlock()
		if !ready {
			return true // ещё создаётся
		}
		if v, _, _ := miniIsVisible.Call(h); v != 0 {
			miniHide(h)
			return true
		}
		if justHidden { // щелчок по значку сам отнял у панели фокус и спрятал её: значит, её хотели закрыть
			return true
		}
		miniShowAtCursor(h)
		return true
	}
	mini.open = true
	mini.Unlock()

	ok := make(chan bool, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		comInit() // WebView2 требует COM в каждом потоке, где создаётся окно (иначе ошибка 800401f0)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("мини-панель: паника: %v\n%s", r, debug.Stack())
				select {
				case ok <- false:
				default:
				}
			}
			mini.Lock()
			mini.open, mini.ready, mini.hwnd, mini.w = false, false, 0, nil
			mini.Unlock()
		}()
		if err := loadWebView2Loader(dataDir); err != nil {
			log.Printf("мини-панель: загрузчик WebView2: %v", err)
			ok <- false
			return
		}
		if v, err := webviewloader.GetInstalledVersion(); err != nil || v == "" {
			log.Printf("мини-панель: среда WebView2 не найдена (%v)", err)
			ok <- false
			return
		}
		webview2.OnActivate = func(h uintptr, active bool, other uintptr) { miniOnActivate(h, active, other) }
		if webview2.OnClose == nil { // главное окно ещё не открывали: Alt+F4 на панели только прячет её
			webview2.OnClose = func(h uintptr) bool {
				if isMiniWindow(h) {
					miniHide(h)
					return true
				}
				return false
			}
		}
		failed := false
		edge.OnFail = func(msg string) { log.Printf("мини-панель: %s", msg); failed = true }
		w := webview2.NewWithOptions(webview2.WebViewOptions{
			// своя папка данных: вторая среда WebView2 с той же папкой в этом же процессе не создаётся (Windows отказывает)
			DataPath:      filepath.Join(dataDir, "webview2-mini"),
			AutoFocus:     true,
			WindowOptions: webview2.WindowOptions{Title: appName, Width: miniW, Height: miniH, Popup: true},
		})
		if w == nil || failed {
			log.Printf("мини-панель: окно не создалось (w=%v, failed=%v)", w != nil, failed)
			ok <- false
			return
		}
		defer w.Destroy()
		h := uintptr(w.Window())
		// скруглённые углы и тёмная рамка в Windows 11 (в Windows 10 эти вызовы просто ничего не делают)
		wvDwmSet(h, 33, 2) // DWMWA_WINDOW_CORNER_PREFERENCE = DWMWCP_ROUND
		wvDwmSet(h, 20, 1) // DWMWA_USE_IMMERSIVE_DARK_MODE
		_ = w.Bind("obhodOpen", func() {
			miniHide(h)
			go openMain()
		})
		_ = w.Bind("obhodHide", func() { miniHide(h) })
		mini.Lock()
		mini.hwnd, mini.w, mini.ready = h, w, true
		mini.Unlock()
		w.Navigate(url)
		miniShowAtCursor(h)
		ok <- true
		w.Run()
	}()
	return <-ok
}

// miniShowAtCursor ставит панель над значком в трее (по месту курсора, внутри рабочей области экрана) и показывает её.
func miniShowAtCursor(h uintptr) {
	var pt struct{ X, Y int32 }
	_, _, _ = miniCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	scale := 1.0
	if dpi, _, _ := miniDpiForWindow.Call(h); dpi >= 96 {
		scale = float64(dpi) / 96
	}
	w, hh := int32(float64(miniW)*scale), int32(float64(miniH)*scale)
	work := wvRect{0, 0, 1920, 1040}
	mon, _, _ := miniMonFromPt.Call(uintptr(*(*uint64)(unsafe.Pointer(&pt))), 2) // MONITOR_DEFAULTTONEAREST
	mi := miniMonitorInfo{CbSize: uint32(unsafe.Sizeof(miniMonitorInfo{}))}
	if r, _, _ := miniMonInfo.Call(mon, uintptr(unsafe.Pointer(&mi))); r != 0 {
		work = mi.RcWork
	}
	x, y := miniPlace(pt.X, pt.Y, w, hh, work, int32(10*scale))
	// сначала ставим на место (ещё скрытой), потом показываем через ShowWindow: только так окно получает WM_SHOWWINDOW,
	// и встроенный браузер включает отрисовку (иначе панель видна пустой и прозрачной)
	_, _, _ = miniSetWindowPos.Call(h, ^uintptr(0) /* HWND_TOPMOST */, uintptr(x), uintptr(y), uintptr(w), uintptr(hh), 0x0010) // SWP_NOACTIVATE
	_, _, _ = miniShowWindow.Call(h, 5)                                                                                         // SW_SHOW
	_, _, _ = miniSetFg.Call(h)
	mini.Lock()
	mini.gen++
	wv := mini.w
	mini.Unlock()
	if wv != nil {
		wv.Dispatch(wv.Reveal) // на всякий случай включаем отрисовку явно, в потоке окна
	}
}

func miniHide(h uintptr) {
	_, _, _ = miniShowWindow.Call(h, 0) // SW_HIDE
	mini.Lock()
	mini.hiddenAt = time.Now()
	gen := mini.gen
	mini.Unlock()
	// долго не открывали — закрываем окно совсем, чтобы не держать память (откроется заново за секунду)
	time.AfterFunc(miniIdle, func() {
		mini.Lock()
		defer mini.Unlock()
		if mini.w == nil || mini.gen != gen || mini.hwnd != h {
			return
		}
		if v, _, _ := miniIsVisible.Call(h); v != 0 {
			return
		}
		w := mini.w
		w.Dispatch(w.Terminate)
	})
}

var miniGetAncestor = miniU32.NewProc("GetAncestor")

// miniOnActivate: щелчок мимо панели — прячем её. other — окно, которое получает фокус (lParam у WM_ACTIVATE).
// Встроенный браузер живёт в отдельном процессе; если фокус ушёл в его окно внутри панели, это не «мимо».
func miniOnActivate(h uintptr, active bool, other uintptr) bool {
	mini.Lock()
	is := mini.hwnd != 0 && h == mini.hwnd
	mini.Unlock()
	if !is || active {
		return is
	}
	if other != 0 {
		if root, _, _ := miniGetAncestor.Call(other, 2); root == h { // GA_ROOT
			log.Printf("мини-панель: фокус ушёл внутрь панели — не прячем")
			return is
		}
	}
	miniHide(h)
	return is
}

func isMiniWindow(h uintptr) bool {
	mini.Lock()
	defer mini.Unlock()
	return mini.hwnd != 0 && h == mini.hwnd
}

var procCoInit = syscall.NewLazyDLL("ole32.dll").NewProc("CoInitializeEx")

// comInit готовит текущий поток для COM в режиме однопоточного подразделения (как требует WebView2).
// Повторный вызов в том же потоке безвреден.
func comInit() {
	if r, _, _ := procCoInit.Call(0, 2); int32(r) < 0 { // COINIT_APARTMENTTHREADED
		log.Printf("COM: CoInitializeEx: %08x", uint32(r))
	}
}
