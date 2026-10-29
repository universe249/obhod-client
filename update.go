package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const updateRepo = "universe249/obhodch"

// Public half of the release signing key (private half stays with the author).
var updatePubKey = "5+RcDKqXJRjDz7XPaz4ubeUhK0rXSKvNIQY7/CXL5F4="

var updateAPIBase = "https://api.github.com"

type updateManifest struct {
	Version string `json:"version"`
	File    string `json:"file"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

type Updater struct {
	mu       sync.Mutex
	Latest   string
	Notes    string
	Checked  time.Time
	Err      string
	Busy     bool
	Stage    string // "", checking, downloading, verifying, installing
	Done     int64
	Total    int64
	fileURL  string
	manifest updateManifest
	notified string
}

func (u *Updater) snapshot() map[string]any {
	u.mu.Lock()
	defer u.mu.Unlock()
	return map[string]any{
		"current": appVersion, "latest": u.Latest, "notes": u.Notes,
		"available": u.Latest != "" && newerVersion(u.Latest, appVersion),
		"checked":   u.Checked.Format("15:04"), "error": u.Err, "busy": u.Busy,
		"stage": u.Stage, "done": u.Done, "total": u.Total,
		"canUpdate": appVersion != "dev",
	}
}

func newerVersion(a, b string) bool {
	pa, pb := splitVer(a), splitVer(b)
	if pa == nil || pb == nil {
		return false
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func splitVer(v string) []int {
	var out []int
	for _, p := range strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

func httpGet(url string, limit int64) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "obhod-updater")
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("файл слишком большой")
	}
	return b, nil
}

func verifyManifest(manifest, sigB64 []byte) error {
	pub, err := base64.StdEncoding.DecodeString(updatePubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("в программе нет ключа проверки")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), manifest, sig) {
		return errors.New("подпись обновления неверна — установка отменена")
	}
	return nil
}

// check asks GitHub for the latest release and verifies its signed manifest.
func (u *Updater) check() error {
	u.mu.Lock()
	own := u.Stage == ""
	if own {
		u.Stage = "checking"
	}
	u.mu.Unlock()
	if own {
		defer u.setStage("", 0, 0)
	}
	var rel struct {
		Tag    string `json:"tag_name"`
		Body   string `json:"body"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	b, err := httpGet(updateAPIBase+"/repos/"+updateRepo+"/releases/latest", 1<<20)
	if err == nil {
		err = json.Unmarshal(b, &rel)
	}
	if err != nil {
		return u.fail("не удалось проверить обновления: " + err.Error())
	}
	urls := map[string]string{}
	for _, a := range rel.Assets {
		urls[a.Name] = a.URL
	}
	if urls["manifest.json"] == "" || urls["manifest.json.sig"] == "" {
		return u.fail("в релизе нет manifest.json и manifest.json.sig")
	}
	man, err1 := httpGet(urls["manifest.json"], 64<<10)
	sig, err2 := httpGet(urls["manifest.json.sig"], 4<<10)
	if err1 != nil || err2 != nil {
		return u.fail("не удалось скачать манифест обновления")
	}
	if err := verifyManifest(man, sig); err != nil {
		return u.fail(err.Error())
	}
	var m updateManifest
	if json.Unmarshal(man, &m) != nil || m.Version == "" || m.SHA256 == "" || urls[m.File] == "" {
		return u.fail("манифест обновления повреждён")
	}
	u.mu.Lock()
	u.Latest, u.Notes, u.Checked, u.Err = strings.TrimPrefix(m.Version, "v"), strings.TrimSpace(rel.Body), time.Now(), ""
	u.fileURL, u.manifest = urls[m.File], m
	u.mu.Unlock()
	return nil
}

func (u *Updater) setStage(stage string, done, total int64) {
	u.mu.Lock()
	u.Stage, u.Done, u.Total = stage, done, total
	u.mu.Unlock()
}

// httpGetProgress downloads url and reports the bytes received so far.
func httpGetProgress(url string, limit int64, onProg func(done, total int64)) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "obhod-updater")
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	total := resp.ContentLength
	var buf bytes.Buffer
	chunk := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			if int64(buf.Len()) > limit {
				return nil, errors.New("файл слишком большой")
			}
			onProg(int64(buf.Len()), total)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (u *Updater) fail(msg string) error {
	u.mu.Lock()
	u.Err, u.Checked = msg, time.Now()
	u.mu.Unlock()
	return errors.New(msg)
}

// download fetches the archive, checks it against the signed manifest and returns the new exe bytes.
func (u *Updater) download() ([]byte, error) {
	u.mu.Lock()
	url, m := u.fileURL, u.manifest
	u.mu.Unlock()
	if url == "" {
		return nil, errors.New("сначала проверь обновления")
	}
	u.setStage("downloading", 0, m.Size)
	data, err := httpGetProgress(url, 100<<20, func(done, total int64) {
		if total <= 0 {
			total = m.Size
		}
		u.setStage("downloading", done, total)
	})
	if err != nil {
		return nil, errors.New("не удалось скачать обновление: " + err.Error())
	}
	u.setStage("verifying", int64(len(data)), int64(len(data)))
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), m.SHA256) {
		return nil, errors.New("контрольная сумма не совпала — установка отменена")
	}
	return exeFromZip(data)
}

func exeFromZip(data []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errors.New("архив повреждён")
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.EqualFold(filepath.Ext(f.Name), ".exe") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, 150<<20))
		if err != nil {
			return nil, err
		}
		if len(b) < 1<<20 || b[0] != 'M' || b[1] != 'Z' {
			return nil, errors.New("в архиве нет программы")
		}
		return b, nil
	}
	return nil, errors.New("в архиве нет exe-файла")
}

// swapExe replaces the running executable with newExe, keeping the old one as .bak.
func swapExe(exe string, newExe []byte) error {
	nw, bak := exe+".new", exe+".bak"
	if err := os.WriteFile(nw, newExe, 0o755); err != nil {
		return err
	}
	_ = os.Remove(bak)
	if err := os.Rename(exe, bak); err != nil {
		os.Remove(nw)
		return err
	}
	if err := os.Rename(nw, exe); err != nil {
		_ = os.Rename(bak, exe)
		return err
	}
	return nil
}

func (a *App) updateLoop() {
	time.Sleep(25 * time.Second)
	for {
		if appVersion != "dev" {
			if a.upd.check() == nil {
				s := a.upd.snapshot()
				v, _ := s["latest"].(string)
				if s["available"] == true {
					a.upd.mu.Lock()
					first := a.upd.notified != v
					a.upd.notified = v
					a.upd.mu.Unlock()
					if first {
						a.notify(appName, "Доступна новая версия "+v+". Открой программу и нажми «Обновить».")
					}
				}
			}
		}
		select {
		case <-a.quit:
			return
		case <-time.After(6 * time.Hour):
		}
	}
}

// POST /api/update {action: check|install}; GET returns the status.
func (a *App) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, 200, a.upd.snapshot())
		return
	}
	var in struct {
		Action string `json:"action"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	switch in.Action {
	case "check":
		if err := a.upd.check(); err != nil {
			fail(w, 502, err.Error())
			return
		}
		writeJSON(w, 200, a.upd.snapshot())
	case "rollback":
		a.doRollback(w)
	case "install":
		if appVersion == "dev" {
			fail(w, 400, "это тестовая сборка, обновление отключено")
			return
		}
		a.upd.mu.Lock()
		if a.upd.Busy {
			a.upd.mu.Unlock()
			fail(w, 409, "обновление уже идёт")
			return
		}
		a.upd.Busy = true
		a.upd.mu.Unlock()
		defer func() { a.upd.mu.Lock(); a.upd.Busy = false; a.upd.mu.Unlock(); a.upd.setStage("", 0, 0) }()
		if err := a.upd.check(); err != nil {
			fail(w, 502, err.Error())
			return
		}
		if !newerVersion(a.upd.snapshot()["latest"].(string), appVersion) {
			fail(w, 400, "у тебя уже последняя версия")
			return
		}
		exeBytes, err := a.upd.download()
		if err != nil {
			fail(w, 502, err.Error())
			return
		}
		exe, err := os.Executable()
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		a.upd.setStage("installing", 0, 0)
		wasOn := a.core.Running() || a.wanted()
		a.core.Stop()
		if err := swapExe(exe, exeBytes); err != nil {
			if wasOn {
				_ = startedOK(a.core.Start(a.settings())) // the old version keeps working
			}
			fail(w, 500, "не удалось заменить файл программы: "+err.Error())
			return
		}
		if err := relaunchSelf(exe, wasOn); err != nil {
			fail(w, 500, "обновлено, но не удалось перезапустить — запусти программу вручную: "+err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "restarting": true})
		go func() {
			time.Sleep(500 * time.Millisecond)
			a.doQuit()
		}()
	default:
		fail(w, 400, "неизвестное действие")
	}
}
