package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// errAlreadyRunning: Start was called while the core is up (callers that only want "make sure it runs" accept it).
var errAlreadyRunning = errors.New("уже запущено")

// startedOK: a restart (Stop, then Start) can lose the race to another start in between; the tunnel runs, so it is fine.
func startedOK(err error) error {
	if errors.Is(err, errAlreadyRunning) {
		return nil
	}
	return err
}

type Core struct {
	lifeMu    sync.Mutex // Start and Stop run one at a time: a restart takes seconds and several goroutines can ask for one
	mu        sync.Mutex
	dataDir   string
	cmd       *exec.Cmd
	stdin     io.WriteCloser // закрыть = попросить ядро остановиться
	done      chan struct{}
	xcmd      *exec.Cmd
	xdone     chan struct{}
	startedAt time.Time
	stopping  bool
	lastErr   string
	onCrash   func(msg string) // вызывается, когда sing-box упал сам
	cfgHash   string
	version   string
	skip      map[string]bool
	warnings  []string
}

// Skip returns a copy of the rule-sets that were left out at the last start.
func (c *Core) Skip() map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]bool{}
	for k, v := range c.skip {
		out[k] = v
	}
	return out
}

func (c *Core) Warnings() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.warnings...)
}

// binPath — программа, в которую встроено ядро (она же запускается с ключом -core). Пустая строка — не нашлась.
func (c *Core) binPath(st Settings) string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if runtime.GOOS != "windows" {
		return exe
	}
	return coreAlias(exe, c.dataDir)
}

// coreExeName — под каким именем запускается ядро на Windows.
const coreExeName = "obhod-core.exe"

// coreAlias даёт ядру путь только из латиницы: data\obhod-core.exe — жёсткая ссылка на программу (места не занимает).
// Зачем: в режиме strict_route ядро ставит фильтр Windows (WFP), который блокирует DNS на порт 53 мимо туннеля для всех,
// кроме самого ядра, а ядро Windows узнаёт по пути к exe. С путём «C:\…\Обход для чайников.exe» исключение не
// срабатывало: прямые DNS-запросы ядра (локальный DNS) блокировались, и все сайты «напрямую» переставали открываться.
// Если ссылку сделать нельзя — копия; если и это не вышло — запускаем саму программу.
func coreAlias(exe, dataDir string) string {
	dst := filepath.Join(coreDir(dataDir), coreExeName)
	ei, err := os.Stat(exe)
	if err != nil {
		return exe
	}
	if di, err := os.Stat(dst); err == nil && (os.SameFile(ei, di) || (di.Size() == ei.Size() && di.ModTime().Equal(ei.ModTime()))) {
		return dst
	}
	_ = os.Remove(dst)
	if err := os.Link(exe, dst); err == nil {
		return dst
	}
	if err := copyFileTimes(exe, dst); err == nil {
		return dst
	}
	log.Printf("ядро: не удалось подготовить %s, запускаю из программы", dst)
	return exe
}

// coreDir — папка для ядра: data, если путь к ней только из латиницы, иначе C:\ProgramData\Obhod
// (при установке через установщик папка программы называется по-русски).
func coreDir(dataDir string) string {
	if isASCII(dataDir) {
		return dataDir
	}
	if pd := os.Getenv("ProgramData"); pd != "" && isASCII(pd) {
		d := filepath.Join(pd, "Obhod")
		if os.MkdirAll(d, 0o755) == nil {
			return d
		}
	}
	return dataDir
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func copyFileTimes(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	_ = os.Chtimes(tmp, fi.ModTime(), fi.ModTime())
	return os.Rename(tmp, dst)
}

// coreCmd — команда встроенного ядра: эта же программа с ключом -core.
func coreCmd(bin string, args ...string) *exec.Cmd {
	cmd := exec.Command(bin, append([]string{coreFlag}, args...)...)
	if os.Getenv("SINGUI_DATA") != "" {
		cmd.Env = os.Environ()
	}
	return cmd
}

func (c *Core) xrayBin(st Settings) string {
	cands := []string{}
	if st.XrayPath != "" {
		cands = append(cands, st.XrayPath)
	}
	cands = append(cands, filepath.Join(c.dataDir, "xray.exe"), filepath.Join(c.dataDir, "xray"))
	for _, p := range cands {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func (c *Core) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cmd != nil
}

func (c *Core) Info() (running bool, pid int, uptime time.Duration, lastErr, hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd != nil {
		running = true
		pid = c.cmd.Process.Pid
		uptime = time.Since(c.startedAt)
	}
	return running, pid, uptime, c.lastErr, c.cfgHash
}

// Version — версия встроенного ядра.
func (c *Core) Version(bin string) string { return embeddedCoreVersion() }

func tailFile(path string, maxBytes int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	start := int64(0)
	if fi.Size() > maxBytes {
		start = fi.Size() - maxBytes
	}
	buf := make([]byte, fi.Size()-start)
	n, _ := f.ReadAt(buf, start)
	return string(buf[:n])
}

func (c *Core) Start(st Settings) error {
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	c.mu.Lock()
	if c.cmd != nil {
		c.mu.Unlock()
		return errAlreadyRunning
	}
	c.mu.Unlock()

	if secretsLostFor(st.Server) {
		msg := "пароль сервера не прочитался: настройки зашифрованы под другим пользователем Windows. Старые данные сохранены в data\\" + unreadableBackup + ". Запусти программу под тем же пользователем или добавь сервер заново"
		c.setErr(msg)
		return errors.New(msg)
	}
	hostIPs.refresh(c.dataDir, st)
	bin := c.binPath(st)
	if bin == "" {
		return errors.New("не удалось определить путь к программе — переустанови её")
	}
	// An old sing-box (previous run, the old console window...) can hold cache.db and the TUN adapter.
	killAllCore(c.dataDir)
	// Старый процесс может завершаться дольше 700 мс (закрывает TUN, антивирус проверяет): пока он жив, новый не запустится
	// («initialize cache-file: timeout»). Ждём до 10 секунд и повторяем kill.
	for i := 0; i < 20 && coreRunning(c.dataDir); i++ {
		time.Sleep(500 * time.Millisecond)
		if i%4 == 3 {
			killAllCore(c.dataDir)
		}
	}
	time.Sleep(300 * time.Millisecond)
	removeLegacyCore(c.dataDir)

	// local rule-sets: download what is missing; unavailable ones are skipped with a warning
	missing, _ := ensureRuleSets(st, c.dataDir, false)
	skip := map[string]bool{}
	for _, t := range missing {
		skip[t] = true
	}
	var warns []string
	if len(missing) > 0 {
		warns = append(warns, "Не удалось скачать списки сайтов: "+strings.Join(missing, ", ")+". Они пропущены, нажми «Обновить списки» на вкладке «Правила», когда появится интернет.")
	}

	pinServers(st, c.dataDir) // the tunnel is down here, so the lookup goes straight out
	cfg, err := configBytes(st, c.dataDir, skip)
	if err != nil {
		c.setErr(err.Error())
		return err
	}
	cfgPath := filepath.Join(c.dataDir, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return err
	}

	// Сразу после перезапуска Windows/антивирус могут ещё держать файл программы («Access is denied», пустой вывод):
	// пробуем несколько раз, а не сдаёмся с пустой ошибкой.
	var chkErr error
	var chkOut string
	for try := 0; try < 4; try++ {
		chk := coreCmd(bin, "check", "-c", cfgPath, "-D", c.dataDir)
		hide(chk)
		out, err := chk.CombinedOutput()
		chkOut = strings.TrimSpace(stripANSI(string(out)))
		chkErr = err
		if err == nil || (chkOut != "" && !transientExecErr(chkOut)) {
			break
		}
		time.Sleep(1500 * time.Millisecond)
	}
	if chkErr != nil {
		if chkOut == "" {
			chkOut = chkErr.Error()
		}
		msg := "конфиг не прошёл проверку: " + chkOut
		c.setErr(msg)
		return errors.New(msg)
	}

	if needsXray(st.Server) {
		if err := c.startXray(st); err != nil {
			c.setErr(err.Error())
			return err
		}
	}

	_ = os.Remove(filepath.Join(c.dataDir, "box.log"))
	outFile, err := os.Create(filepath.Join(c.dataDir, "core.out"))
	if err != nil {
		c.stopXray()
		return err
	}
	var cmd *exec.Cmd
	var startErr error
	var stdinW io.WriteCloser
	for try := 0; try < 4; try++ {
		cmd = coreCmd(bin, "run", "-c", cfgPath, "-D", c.dataDir)
		cmd.Dir = c.dataDir
		cmd.Stdout = outFile
		cmd.Stderr = outFile
		hide(cmd)
		// ядро живёт, пока открыт его stdin: закрыв его, окно мягко останавливает туннель (TUN убирается как положено)
		stdin, perr := cmd.StdinPipe()
		if perr != nil {
			startErr = perr
			break
		}
		startErr = cmd.Start()
		if startErr != nil {
			stdin.Close()
		} else {
			stdinW = stdin
		}
		if startErr == nil || !transientExecErr(startErr.Error()) {
			break
		}
		time.Sleep(1500 * time.Millisecond)
	}
	if err := startErr; err != nil {
		outFile.Close()
		c.stopXray()
		c.setErr(err.Error())
		return err
	}
	assignToJob(cmd.Process.Pid)
	writeCorePID(c.dataDir, cmd.Process.Pid)
	go refreshStale(st, c.dataDir, 72*time.Hour)

	done := make(chan struct{})
	c.mu.Lock()
	c.cmd = cmd
	c.stdin = stdinW
	c.done = done
	c.startedAt = time.Now()
	c.stopping = false
	c.lastErr = ""
	c.cfgHash = fullHash(st, c.dataDir, skip)
	c.skip = skip
	c.warnings = warns
	c.mu.Unlock()

	go c.reap(cmd, outFile, done)
	return nil
}

// reap waits for the sing-box process and records how it ended. A process that a newer start has already replaced
// (a slow Stop, two restarts racing) must not touch the newer one's state or report a crash.
func (c *Core) reap(cmd *exec.Cmd, outFile *os.File, done chan struct{}) {
	werr := cmd.Wait()
	if outFile != nil {
		outFile.Close()
	}
	crash := ""
	c.mu.Lock()
	own := c.cmd == cmd
	if own && !c.stopping && werr != nil {
		msg := strings.TrimSpace(stripANSI(tailFile(filepath.Join(c.dataDir, "core.out"), 4000)))
		if msg == "" {
			msg = werr.Error()
		}
		c.lastErr = "sing-box остановился: " + msg
		crash = msg
	}
	if own {
		c.cmd = nil
		c.stdin = nil
		removeCorePID(c.dataDir, cmd.Process.Pid)
	}
	hook := c.onCrash
	c.mu.Unlock()
	if crash != "" && hook != nil {
		hook(crash)
	}
	if own {
		c.stopXray()
	}
	close(done)
}

func (c *Core) setErr(s string) {
	c.mu.Lock()
	c.lastErr = s
	c.mu.Unlock()
}

func (c *Core) Stop() {
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	c.mu.Lock()
	cmd, done, stdin := c.cmd, c.done, c.stdin
	if cmd == nil {
		c.mu.Unlock()
		c.stopXray()
		return
	}
	c.stopping = true
	c.mu.Unlock()
	// сначала просим ядро закрыться самому (убрать TUN и маршруты), через 3 секунды — принудительно
	if stdin != nil {
		_ = stdin.Close()
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
	c.stopXray()
}

// ---- clash API helpers ----

var apiClient = &http.Client{Timeout: 2500 * time.Millisecond}

func clashGet(st Settings, path string, out any) error {
	req, _ := http.NewRequest("GET", "http://127.0.0.1:"+itoa(st.APIPort)+path, nil)
	req.Header.Set("Authorization", "Bearer "+st.APISecret)
	resp, err := apiClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("clash api %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// removeLegacyCore удаляет отдельное ядро прошлых версий (sing-box.exe ~80 МБ и libcronet.dll): оно больше не нужно.
// Пока рядом лежит копия для отката на прошлую версию (.bak), ядро оставляем: откаченной версии оно понадобится.
// Удаляем, когда .bak сменился (следующее обновление: в нём уже версия со встроенным ядром) или пропал.
func removeLegacyCore(dir string) {
	if _, err := os.Stat(filepath.Join(dir, "sing-box.exe")); err != nil {
		return
	}
	mark := filepath.Join(dir, "legacy-core-bak.txt")
	if exe, err := os.Executable(); err == nil {
		if fi, err := os.Stat(exe + ".bak"); err == nil {
			cur := itoa(int(fi.ModTime().Unix()))
			b, err := os.ReadFile(mark)
			if err != nil {
				_ = os.WriteFile(mark, []byte(cur), 0o600)
				return
			}
			if strings.TrimSpace(string(b)) == cur {
				return
			}
		}
	}
	for _, n := range []string{"sing-box.exe", "libcronet.dll", "legacy-core-bak.txt"} {
		_ = os.Remove(filepath.Join(dir, n))
	}
}

// ---- PID ядра ----

// Номер процесса ядра пишем в data\core.pid: если программа упала, при следующем запуске оставшееся ядро
// (оно держит TUN и cache.db) найдётся и будет остановлено.
func writeCorePID(dir string, pid int) {
	_ = os.WriteFile(filepath.Join(dir, "core.pid"), []byte(itoa(pid)), 0o600)
}

func removeCorePID(dir string, pid int) {
	p := filepath.Join(dir, "core.pid")
	if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) == itoa(pid) {
		_ = os.Remove(p)
	}
}

func readCorePID(dir string) int {
	b, err := os.ReadFile(filepath.Join(dir, "core.pid"))
	if err != nil {
		return 0
	}
	n := 0
	for _, ch := range strings.TrimSpace(string(b)) {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

// ---- Xray (xhttp transport) ----

func (c *Core) startXray(st Settings) error {
	bin := c.xrayBin(st)
	if bin == "" {
		return errors.New("не найден xray.exe — нажми «Скачать / обновить Xray» в «Настройки → Обновления»")
	}
	xcfg, err := xrayConfigBytes(st, c.dataDir)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(c.dataDir, "xray.json")
	if err := os.WriteFile(cfgPath, xcfg, 0o600); err != nil {
		return err
	}
	addr := "127.0.0.1:" + itoa(st.XrayPort)
	if ln, err := net.Listen("tcp", addr); err != nil {
		return fmt.Errorf("порт %d уже занят (запущен другой Xray?) — закрой его или смени порт", st.XrayPort)
	} else {
		ln.Close()
	}

	_ = os.Remove(filepath.Join(c.dataDir, "xray.log"))
	outFile, err := os.Create(filepath.Join(c.dataDir, "xray.out"))
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Dir = c.dataDir
	cmd.Stdout = outFile
	cmd.Stderr = outFile
	hide(cmd)
	if err := cmd.Start(); err != nil {
		outFile.Close()
		return err
	}
	assignToJob(cmd.Process.Pid)
	done := make(chan struct{})
	c.mu.Lock()
	c.xcmd = cmd
	c.xdone = done
	c.mu.Unlock()

	go func() {
		werr := cmd.Wait()
		outFile.Close()
		c.mu.Lock()
		stopping := c.stopping
		own := c.xcmd == cmd
		if own {
			c.xcmd = nil
		}
		if own && !stopping && c.cmd != nil {
			msg := strings.TrimSpace(stripANSI(tailFile(filepath.Join(c.dataDir, "xray.out"), 3000)))
			if msg == "" {
				msg = fmt.Sprint(werr)
			}
			c.lastErr = "Xray остановился: " + msg
			go c.Stop()
		}
		c.mu.Unlock()
		close(done)
	}()

	// wait until the local SOCKS port is up
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			msg := strings.TrimSpace(stripANSI(tailFile(filepath.Join(c.dataDir, "xray.out"), 3000)))
			return errors.New("Xray не запустился: " + msg)
		default:
		}
		if conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("Xray не открыл локальный порт за 8 секунд, нажми «Найти проблему» в «Помощи» или отправь отчёт администратору")
}

func (c *Core) stopXray() {
	c.mu.Lock()
	cmd, done := c.xcmd, c.xdone
	c.xcmd = nil
	c.mu.Unlock()
	if cmd == nil {
		return
	}
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

func (c *Core) DownloadXray() (string, error) {
	if c.Running() {
		return "", errors.New("сначала выключи туннель")
	}
	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Get("https://api.github.com/repos/XTLS/Xray-core/releases/latest")
	if err != nil {
		return "", fmt.Errorf("GitHub недоступен: %w", err)
	}
	defer resp.Body.Close()
	var rel struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	url := ""
	for _, a := range rel.Assets {
		if a.Name == "Xray-windows-64.zip" {
			url = a.URL
			break
		}
	}
	if url == "" {
		return "", errors.New("в последнем релизе нет Xray-windows-64.zip")
	}
	zr, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer zr.Body.Close()
	data, err := io.ReadAll(zr.Body)
	if err != nil {
		return "", err
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	found := false
	for _, f := range z.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := filepath.Base(f.Name)
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(c.dataDir, name), b, 0o755); err != nil {
			return "", err
		}
		if strings.EqualFold(name, "xray.exe") {
			found = true
		}
	}
	if !found {
		return "", errors.New("в архиве нет xray.exe")
	}
	return rel.Tag, nil
}

// transientExecErr — ошибки запуска, которые обычно проходят сами через секунду (файл ещё занят системой или антивирусом).
func transientExecErr(m string) bool {
	m = strings.ToLower(m)
	return strings.Contains(m, "access is denied") || strings.Contains(m, "отказано в доступе") ||
		strings.Contains(m, "being used by another process") || strings.Contains(m, "text file busy")
}
