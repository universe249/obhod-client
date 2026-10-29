//go:build windows

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"github.com/jchv/go-webview2/pkg/edge"
	"github.com/jchv/go-webview2/webviewloader"
)

// Своё окно программы на WebView2 (движок Edge, но без самого браузера: ни вкладок, ни адресной строки).
// Если WebView2 нет или он не запустился, вызывается прежний способ — окно браузера.

var (
	wvMu   sync.Mutex
	wvOpen bool
	wvWnd  unsafe.Pointer
)

// loadWebView2Loader кладёт встроенный WebView2Loader.dll в папку данных и подключает его.
func loadWebView2Loader(dataDir string) error {
	dll := filepath.Join(dataDir, "WebView2Loader.dll")
	if b, err := os.ReadFile(dll); err != nil || len(b) != len(webviewloader.WebView2Loader) {
		if err := os.WriteFile(dll, webviewloader.WebView2Loader, 0o755); err != nil {
			return err
		}
	}
	if _, err := syscall.LoadLibrary(dll); err != nil {
		return err
	}
	webviewloader.SetPath(dll)
	return nil
}

// openWebviewWindow открывает окно и возвращает true, если оно создано. Окно живёт в своём потоке.
func openWebviewWindow(url, dataDir string, fallback func()) bool {
	wvMu.Lock()
	if wvOpen {
		if wvWnd != nil {
			u32 := syscall.NewLazyDLL("user32.dll")
			_, _, _ = u32.NewProc("ShowWindow").Call(uintptr(wvWnd), 5) // SW_SHOW (если скрыто в трей)
			_, _, _ = u32.NewProc("ShowWindow").Call(uintptr(wvWnd), 9) // SW_RESTORE
			_, _, _ = u32.NewProc("SetForegroundWindow").Call(uintptr(wvWnd))
		}
		wvMu.Unlock()
		return true
	}
	// Защита от «окно роняет программу при каждом запуске»: пока файл-метка лежит, окно не пробуем (открываем в браузере).
	// Метка снимается, когда окно проработало 15 секунд. Чтобы попробовать снова, удалите data\\webview.try.
	mark := filepath.Join(dataDir, "webview.try")
	// метка от другой версии программы не считается: ошибка могла быть уже исправлена
	if b, err := os.ReadFile(mark); err == nil && strings.TrimSpace(string(b)) == appVersion {
		wvMu.Unlock()
		log.Printf("webview2: прошлый запуск окна не завершился штатно, открываю в браузере (удалите %s, чтобы попробовать снова)", mark)
		if fallback != nil {
			fallback()
		}
		return false
	}
	_ = os.WriteFile(mark, []byte(appVersion), 0o644)
	wvOpen = true
	wvMu.Unlock()

	ready := make(chan bool, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		comInit()
		done := func() { wvMu.Lock(); wvOpen, wvWnd = false, nil; wvMu.Unlock() }
		defer done()
		failedStart := true
		defer func() {
			if failedStart { // не удалось создать окно штатно: не оставляем метку, это не падение
				_ = os.Remove(mark)
			}
		}()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("webview2: паника: %v\n%s", r, debug.Stack())
				select {
				case ready <- false:
				default:
				}
			}
		}()
		if err := loadWebView2Loader(dataDir); err != nil {
			log.Printf("webview2: загрузчик: %v", err)
			ready <- false
			return
		}
		if v, err := webviewloader.GetInstalledVersion(); err != nil || v == "" {
			log.Printf("webview2: среда не установлена (%v)", err)
			ready <- false
			return
		}
		failed := false
		edge.OnFail = func(msg string) { log.Printf("webview2: %s", msg); failed = true }
		w := webview2.NewWithOptions(webview2.WebViewOptions{
			DataPath:      filepath.Join(dataDir, "webview2"),
			AutoFocus:     true,
			WindowOptions: webview2.WindowOptions{Title: appName, Width: 1060, Height: 760, Center: true},
		})
		if w == nil || failed {
			ready <- false
			return
		}
		defer w.Destroy()
		wvMu.Lock()
		wvWnd = w.Window()
		wvMu.Unlock()
		w.SetSize(1060, 760, webview2.HintNone)
		// минимальный размер окна: меньше интерфейс уже не помещается (до 520 точек меню уезжает вниз, как в мобильных приложениях).
		// Размер задаётся в пикселях экрана, поэтому учитываем масштаб Windows (125 %, 150 %…).
		scale := 1.0
		if dpi, _, _ := syscall.NewLazyDLL("user32.dll").NewProc("GetDpiForWindow").Call(uintptr(w.Window())); dpi >= 96 {
			scale = float64(dpi) / 96
		}
		w.SetSize(int(380*scale), int(540*scale), webview2.HintMin)
		restoreWindowRect(uintptr(w.Window()), dataDir)
		// крестик прячет окно в трей (туннель продолжает работать); выйти можно из меню значка в трее
		webview2.OnClose = func(h uintptr) bool {
			if isMiniWindow(h) { // Alt+F4 на мини-панели: просто прячем её
				miniHide(h)
				return true
			}
			saveWindowRect(h, dataDir)
			_, _, _ = syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow").Call(h, 0) // SW_HIDE
			return true
		}
		hwnd := uintptr(w.Window())
		// интерфейс сообщает свой цвет и тему; заголовок окна (с кнопками свернуть/развернуть/закрыть) красим под них
		_ = w.Bind("obhodTitle", func(dark bool, r, g, b int) {
			// не внутри обработчика сообщения от страницы: смена рамки шлёт окну свои сообщения, это могло вешать окно
			go wvPaintTitle(hwnd, dark, r, g, b)
		})
		w.Navigate(url)
		failedStart = false
		time.AfterFunc(15*time.Second, func() { _ = os.Remove(mark) })
		ready <- true
		w.Run()
		_ = os.Remove(mark) // окно закрыто штатно
	}()
	if ok := <-ready; !ok {
		if fallback != nil {
			fallback()
		}
		return false
	}
	return true
}

var wvDwmDLL = syscall.NewLazyDLL("dwmapi.dll")

func wvDwmSet(hwnd uintptr, attr uint32, val uint32) {
	_, _, _ = wvDwmDLL.NewProc("DwmSetWindowAttribute").Call(hwnd, uintptr(attr), uintptr(unsafe.Pointer(&val)), 4)
}

// wvPaintTitle: только светлый или тёмный заголовок окна (по теме программы), без своих цветов.
// Работает в Windows 10 (2004+) и 11; где не поддерживается, ничего не делает.
func wvPaintTitle(hwnd uintptr, dark bool, r, g, b int) {
	defer func() { _ = recover() }() // покраска заголовка не должна ронять программу
	var d uint32
	if dark {
		d = 1
	}
	wvDwmSet(hwnd, 20, d) // DWMWA_USE_IMMERSIVE_DARK_MODE
}

type wvState struct {
	X, Y, W, H int32
	Max        bool
}

func wvStatePath(dataDir string) string { return filepath.Join(dataDir, "window.json") }

// saveWindowRect запоминает положение и размер окна (не свёрнутого).
func saveWindowRect(hwnd uintptr, dataDir string) {
	defer func() { _ = recover() }()
	u32 := syscall.NewLazyDLL("user32.dll")
	if r, _, _ := u32.NewProc("IsIconic").Call(hwnd); r != 0 {
		return
	}
	var rc wvRect
	if r, _, _ := u32.NewProc("GetWindowRect").Call(hwnd, uintptr(unsafe.Pointer(&rc))); r == 0 {
		return
	}
	zoomed, _, _ := u32.NewProc("IsZoomed").Call(hwnd)
	st := wvState{X: rc.Left, Y: rc.Top, W: rc.Right - rc.Left, H: rc.Bottom - rc.Top, Max: zoomed != 0}
	if zoomed != 0 { // при развёрнутом окне размеры «обычного» не трогаем
		if old, ok := readWvState(dataDir); ok {
			old.Max = true
			st = old
		}
	}
	if b, err := json.Marshal(st); err == nil {
		_ = os.WriteFile(wvStatePath(dataDir), b, 0o600)
	}
}

func readWvState(dataDir string) (wvState, bool) {
	var st wvState
	b, err := os.ReadFile(wvStatePath(dataDir))
	if err != nil || json.Unmarshal(b, &st) != nil {
		return st, false
	}
	return st, true
}

// restoreWindowRect возвращает окно туда, где оно было, если это место ещё есть на экране.
func restoreWindowRect(hwnd uintptr, dataDir string) {
	defer func() { _ = recover() }()
	st, ok := readWvState(dataDir)
	if !ok || st.W < 300 || st.H < 400 || st.W > 8000 || st.H > 6000 {
		return
	}
	u32 := syscall.NewLazyDLL("user32.dll")
	gm := u32.NewProc("GetSystemMetrics")
	vx, _, _ := gm.Call(76) // SM_XVIRTUALSCREEN
	vy, _, _ := gm.Call(77)
	vw, _, _ := gm.Call(78)
	vh, _, _ := gm.Call(79)
	x0, y0, x1, y1 := int32(vx), int32(vy), int32(vx)+int32(vw), int32(vy)+int32(vh)
	// хотя бы заголовок окна должен попадать на экран
	if st.X+st.W < x0+80 || st.X > x1-80 || st.Y < y0-10 || st.Y > y1-60 {
		return
	}
	_, _, _ = u32.NewProc("SetWindowPos").Call(hwnd, 0, uintptr(st.X), uintptr(st.Y), uintptr(st.W), uintptr(st.H), 0x0004|0x0010) // NOZORDER|NOACTIVATE
	if st.Max {
		_, _, _ = u32.NewProc("ShowWindow").Call(hwnd, 3) // SW_MAXIMIZE
	}
}
