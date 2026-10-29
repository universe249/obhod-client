package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

var (
	hwidOnce sync.Once
	hwidVal  string
	hwidFile string // запасной вариант: случайный номер в папке данных (задаётся при запуске)
)

var reGUID = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// deviceID: постоянный номер этого компьютера для привязки подписки (заголовок x-hwid, как у Happ и v2RayTun).
// Берётся из MachineGuid Windows и хешируется: сам идентификатор Windows наружу не уходит. Не вышло — номер установки.
func deviceID() string {
	hwidOnce.Do(func() {
		src := ""
		if runtime.GOOS == "windows" {
			cmd := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid")
			hide(cmd)
			if out, err := cmd.Output(); err == nil {
				src = reGUID.FindString(string(out))
			}
		}
		if src == "" && hwidFile != "" {
			if b, err := os.ReadFile(hwidFile); err == nil {
				src = strings.TrimSpace(string(b))
			}
			if src == "" {
				src = randHex(16)
				_ = os.WriteFile(hwidFile, []byte(src), 0o600)
			}
		}
		if src == "" {
			return
		}
		h := sha256.Sum256([]byte("obhod-hwid:" + strings.ToLower(src)))
		hwidVal = hex.EncodeToString(h[:16])
	})
	return hwidVal
}

// setDeviceHeaders: кто скачивает подписку — для «одна подписка — одно устройство» и списка устройств в боте.
func setDeviceHeaders(req *http.Request) {
	if id := deviceID(); id != "" {
		req.Header.Set("x-hwid", id)
	}
	req.Header.Set("x-device-os", "Windows")
	if h, err := os.Hostname(); err == nil && h != "" {
		req.Header.Set("x-device-model", h)
	}
	req.Header.Set("X-Obhod-App", appVersion)
}
