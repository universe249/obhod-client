//go:build windows

package main

import (
	"encoding/csv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
	procCreateJob     = kernel32.NewProc("CreateJobObjectW")
	procSetJobInfo    = kernel32.NewProc("SetInformationJobObject")
	procAssignJob     = kernel32.NewProc("AssignProcessToJobObject")
	jobHandle         uintptr
)

const createNoWindow = 0x08000000

func isAdmin() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

func hide(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}

// relaunchAsAdmin starts this program again with a UAC prompt.
// registerProtocol связывает obhod:// с программой (для кнопки «Добавить в приложение» из бота). Только для текущего пользователя.
func registerProtocol(exe string) {
	if exe == "" {
		return
	}
	base := `HKCU\Software\Classes\obhod`
	for _, kv := range [][]string{
		{base, "", "URL:Обход для чайников"},
		{base, "URL Protocol", ""},
		{base + `\shell\open\command`, "", `"` + exe + `" "%1"`},
	} {
		args := []string{"add", kv[0], "/f"}
		if kv[1] == "" {
			args = append(args, "/ve")
		} else {
			args = append(args, "/v", kv[1])
		}
		args = append(args, "/d", kv[2])
		cmd := exec.Command("reg", args...)
		hide(cmd)
		_ = cmd.Run()
	}
}

func relaunchAsAdmin() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	quoted := make([]string, 0, len(os.Args))
	for _, a := range os.Args[1:] {
		quoted = append(quoted, `"`+strings.ReplaceAll(a, `"`, "")+`"`)
	}
	args, _ := syscall.UTF16PtrFromString(strings.Join(quoted, " "))
	dir, _ := syscall.UTF16PtrFromString(filepath.Dir(exe))
	r, _, e := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(args)), uintptr(unsafe.Pointer(dir)), 1)
	if r <= 32 {
		return e
	}
	return nil
}

// Job object: child processes die together with this program.
func initJob() {
	h, _, _ := procCreateJob.Call(0, 0)
	if h == 0 {
		return
	}
	type basic struct {
		PerProcessUserTimeLimit int64
		PerJobUserTimeLimit     int64
		LimitFlags              uint32
		MinimumWorkingSetSize   uintptr
		MaximumWorkingSetSize   uintptr
		ActiveProcessLimit      uint32
		Affinity                uintptr
		PriorityClass           uint32
		SchedulingClass         uint32
	}
	type ioCounters struct{ a, b, c, d, e, f uint64 }
	type extended struct {
		Basic                 basic
		IO                    ioCounters
		ProcessMemoryLimit    uintptr
		JobMemoryLimit        uintptr
		PeakProcessMemoryUsed uintptr
		PeakJobMemoryUsed     uintptr
	}
	var info extended
	info.Basic.LimitFlags = 0x2000 // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	r, _, _ := procSetJobInfo.Call(h, 9, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if r != 0 {
		jobHandle = h
	}
}

func assignToJob(pid int) {
	if jobHandle == 0 {
		return
	}
	const access = 0x0100 | 0x0001 // PROCESS_SET_QUOTA | PROCESS_TERMINATE
	ph, err := syscall.OpenProcess(access, false, uint32(pid))
	if err != nil {
		return
	}
	defer syscall.CloseHandle(ph)
	_, _, _ = procAssignJob.Call(jobHandle, uintptr(ph))
}

func openAppWindow(url, dataDir string) {
	if openWebviewWindow(url, dataDir, func() { openBrowserWindow(url, dataDir) }) {
		return
	}
}

// openExternal открывает ссылку программой по умолчанию (браузер; для t.me браузер предложит открыть Telegram).
func openExternal(url string) {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	hide(cmd)
	_ = cmd.Start()
}

// openBrowserWindow — прежний способ: окно Edge/Chrome и других браузеров на Chromium без вкладок, иначе обычный браузер.
func openBrowserWindow(url, dataDir string) {
	candidates := []string{
		os.Getenv("ProgramFiles(x86)") + `\Microsoft\Edge\Application\msedge.exe`,
		os.Getenv("ProgramFiles") + `\Microsoft\Edge\Application\msedge.exe`,
		os.Getenv("ProgramFiles") + `\Google\Chrome\Application\chrome.exe`,
		os.Getenv("ProgramFiles(x86)") + `\Google\Chrome\Application\chrome.exe`,
		os.Getenv("LocalAppData") + `\Google\Chrome\Application\chrome.exe`,
		// другие браузеры на движке Chromium: тоже умеют окно без вкладок (--app)
		os.Getenv("LocalAppData") + `\Yandex\YandexBrowser\Application\browser.exe`,
		os.Getenv("ProgramFiles") + `\BraveSoftware\Brave-Browser\Application\brave.exe`,
		os.Getenv("LocalAppData") + `\BraveSoftware\Brave-Browser\Application\brave.exe`,
		os.Getenv("LocalAppData") + `\Vivaldi\Application\vivaldi.exe`,
		os.Getenv("LocalAppData") + `\Programs\Opera\opera.exe`,
		os.Getenv("LocalAppData") + `\Programs\Opera GX\opera.exe`,
	}
	for _, c := range candidates {
		if c == "" || strings.HasPrefix(c, `\`) {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			cmd := exec.Command(c, "--app="+url, "--user-data-dir="+filepath.Join(dataDir, "webview"),
				"--window-size=1060,760", "--no-first-run", "--no-default-browser-check")
			if cmd.Start() == nil {
				return
			}
		}
	}
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	hide(cmd)
	_ = cmd.Start()
}

// processNames: имена запущенных .exe через снимок процессов Windows (без запуска tasklist.exe —
// тот на каждый вызов создаёт процесс и тратит заметное время процессора).
func processNames() ([]string, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snap)
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []string
	for err = syscall.Process32First(snap, &e); err == nil; err = syscall.Process32Next(snap, &e) {
		out = append(out, syscall.UTF16ToString(e.ExeFile[:]))
	}
	if len(out) == 0 {
		return nil, err
	}
	return out, nil
}

func listProcesses() []string {
	names, err := processNames()
	if err != nil {
		names = tasklistNames()
	}
	set := map[string]bool{}
	for _, n := range names {
		if strings.HasSuffix(strings.ToLower(n), ".exe") {
			set[n] = true
		}
	}
	var res []string
	for k := range set {
		res = append(res, k)
	}
	sort.Slice(res, func(i, j int) bool { return strings.ToLower(res[i]) < strings.ToLower(res[j]) })
	return res
}

// tasklistNames — запасной способ, если снимок процессов недоступен.
func tasklistNames() []string {
	cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")
	hide(cmd)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	rows, _ := csv.NewReader(strings.NewReader(string(out))).ReadAll()
	var res []string
	for _, r := range rows {
		if len(r) > 0 {
			res = append(res, r[0])
		}
	}
	return res
}

// procByPID — имя .exe процесса с этим номером ("" — такого нет).
func procByPID(pid int) string {
	if pid <= 0 {
		return ""
	}
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(snap)
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = syscall.Process32First(snap, &e); err == nil; err = syscall.Process32Next(snap, &e) {
		if int(e.ProcessID) == pid {
			return syscall.UTF16ToString(e.ExeFile[:])
		}
	}
	return ""
}

// leftoverCore — процесс ядра от прошлого запуска (номер из core.pid, и это действительно наша программа).
func leftoverCore(dataDir string) int {
	pid := readCorePID(dataDir)
	if pid <= 0 || pid == os.Getpid() {
		return 0
	}
	exe, _ := os.Executable()
	if n := procByPID(pid); n != "" && (strings.EqualFold(n, filepath.Base(exe)) || strings.EqualFold(n, coreExeName)) {
		return pid
	}
	return 0
}

// killAllCore останавливает ядро, оставшееся от прошлого запуска, и отдельный sing-box.exe старых версий программы.
func killAllCore(dataDir string) string {
	var out []string
	if pid := leftoverCore(dataDir); pid > 0 {
		if p, err := os.FindProcess(pid); err == nil && p.Kill() == nil {
			out = append(out, "остановлено ядро (процесс "+itoa(pid)+")")
		}
	}
	for _, n := range listProcesses() {
		if strings.EqualFold(n, "sing-box.exe") {
			cmd := exec.Command("taskkill", "/F", "/IM", "sing-box.exe")
			hide(cmd)
			b, _ := cmd.CombinedOutput()
			out = append(out, strings.TrimSpace(string(b)))
			break
		}
	}
	return strings.Join(out, "\n")
}

// coreRunning — живо ли ядро от прошлого запуска (или старый sing-box.exe).
func coreRunning(dataDir string) bool {
	if leftoverCore(dataDir) > 0 {
		return true
	}
	for _, n := range listProcesses() {
		if strings.EqualFold(n, "sing-box.exe") {
			return true
		}
	}
	return false
}

// Имя задачи автозапуска не меняем, чтобы не потерять уже созданную.
func taskName() string { return "SingUI" }

// autostartEnabled спрашивается при каждом обновлении окна (раз в 1,5 с), а проверка — это запуск schtasks.exe.
// Поэтому ответ запоминаем на минуту; после включения или выключения автозапуска он обновляется сразу.
var autostartCache struct {
	sync.Mutex
	at time.Time
	on bool
}

func autostartEnabled() bool {
	autostartCache.Lock()
	defer autostartCache.Unlock()
	if time.Since(autostartCache.at) < time.Minute {
		return autostartCache.on
	}
	cmd := exec.Command("schtasks", "/Query", "/TN", taskName())
	hide(cmd)
	autostartCache.on = cmd.Run() == nil
	autostartCache.at = time.Now()
	return autostartCache.on
}

func setAutostart(on bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var cmd *exec.Cmd
	if on {
		cmd = exec.Command("schtasks", "/Create", "/TN", taskName(), "/TR", `"`+exe+`" -background`,
			"/SC", "ONLOGON", "/RL", "HIGHEST", "/F")
	} else {
		cmd = exec.Command("schtasks", "/Delete", "/TN", taskName(), "/F")
	}
	hide(cmd)
	out, err := cmd.CombinedOutput()
	autostartCache.Lock()
	autostartCache.at = time.Time{} // следующий запрос проверит заново
	autostartCache.Unlock()
	if err != nil {
		return &execError{strings.TrimSpace(string(out))}
	}
	return nil
}

type execError struct{ s string }

func (e *execError) Error() string { return e.s }

// relaunchSelf starts the (new) executable a couple of seconds from now, after this process has exited.
func relaunchSelf(exe string, resume bool) error {
	arg := ""
	if resume {
		arg = " -resume" // the tunnel was on before the update: bring it back even without "start with the program"
	}
	cmd := exec.Command("cmd.exe")
	hide(cmd)
	cmd.SysProcAttr.CreationFlags |= 0x00000200 // CREATE_NEW_PROCESS_GROUP
	cmd.SysProcAttr.CmdLine = `cmd.exe /c "ping -n 3 127.0.0.1 >nul & start "" "` + exe + `"` + arg + `"`
	return cmd.Start()
}

// ---- DPAPI ----

var (
	crypt32          = syscall.NewLazyDLL("crypt32.dll")
	procProtectData  = crypt32.NewProc("CryptProtectData")
	procUnprotectDat = crypt32.NewProc("CryptUnprotectData")
	procLocalFree    = kernel32.NewProc("LocalFree")
)

type dataBlob struct {
	cb   uint32
	data *byte
}

func dpapiCall(p *syscall.LazyProc, in []byte) ([]byte, error) {
	if len(in) == 0 {
		return nil, nil
	}
	src := dataBlob{uint32(len(in)), &in[0]}
	var out dataBlob
	r, _, e := p.Call(uintptr(unsafe.Pointer(&src)), 0, 0, 0, 0, 1 /* UI_FORBIDDEN */, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, e
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.data)))
	return append([]byte(nil), unsafe.Slice(out.data, out.cb)...), nil
}

var dpapiProtect = func(b []byte) ([]byte, error) { return dpapiCall(procProtectData, b) }
var dpapiUnprotect = func(b []byte) ([]byte, error) { return dpapiCall(procUnprotectDat, b) }

// ---- title bar theming (Windows 10 1809+ for dark mode, Windows 11 for colours) ----

var (
	user32w           = syscall.NewLazyDLL("user32.dll")
	dwmapi            = syscall.NewLazyDLL("dwmapi.dll")
	procEnumWindows   = user32w.NewProc("EnumWindows")
	procGetClassName  = user32w.NewProc("GetClassNameW")
	procGetWindowText = user32w.NewProc("GetWindowTextW")
	procIsWindowVis   = user32w.NewProc("IsWindowVisible")
	procDwmSetWinAttr = dwmapi.NewProc("DwmSetWindowAttribute")
	themeMu           sync.Mutex
	themeTargets      []uintptr
	enumThemeCallback = syscall.NewCallback(func(hwnd, lparam uintptr) uintptr {
		if v, _, _ := procIsWindowVis.Call(hwnd); v == 0 {
			return 1
		}
		cls := make([]uint16, 64)
		procGetClassName.Call(hwnd, uintptr(unsafe.Pointer(&cls[0])), 64)
		if syscall.UTF16ToString(cls) != "Chrome_WidgetWin_1" {
			return 1
		}
		title := make([]uint16, 256)
		procGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), 256)
		if syscall.UTF16ToString(title) == appName {
			themeTargets = append(themeTargets, hwnd)
		}
		return 1
	})
)

func dwmSet(hwnd uintptr, attr uint32, v uint32) {
	procDwmSetWinAttr.Call(hwnd, uintptr(attr), uintptr(unsafe.Pointer(&v)), 4)
}

// themeAppWindow recolours the caption of our browser app window(s); returns how many were found.
func themeAppWindow(dark bool, bg, text, border uint32) int {
	themeMu.Lock()
	defer themeMu.Unlock()
	themeTargets = themeTargets[:0]
	procEnumWindows.Call(enumThemeCallback, 0)
	d := uint32(0)
	if dark {
		d = 1
	}
	for _, h := range themeTargets {
		dwmSet(h, 20, d) // DWMWA_USE_IMMERSIVE_DARK_MODE
		dwmSet(h, 34, border)
		dwmSet(h, 35, bg)   // DWMWA_CAPTION_COLOR
		dwmSet(h, 36, text) // DWMWA_TEXT_COLOR
	}
	return len(themeTargets)
}

// attachConsole connects the GUI-subsystem exe to the console it was started from, so CLI output is visible.
func attachConsole() (io.Writer, io.Writer) {
	const attachParent = ^uintptr(0) // ATTACH_PARENT_PROCESS = (DWORD)-1
	r, _, _ := kernel32.NewProc("AttachConsole").Call(attachParent)
	if r == 0 {
		return io.Discard, io.Discard
	}
	kernel32.NewProc("SetConsoleOutputCP").Call(65001)
	f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		return io.Discard, io.Discard
	}
	return f, f
}
