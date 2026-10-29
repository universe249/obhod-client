package main

import (
	"bytes"
	"encoding/base64"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// Secrets in settings.json are encrypted with Windows DPAPI (bound to the Windows user).
// protectFn/unprotectFn are nil where DPAPI is unavailable; then values stay as they are.

const encPrefix = "dpapi:"

var (
	protectFn   func([]byte) ([]byte, error) = dpapiProtect
	unprotectFn func([]byte) ([]byte, error) = dpapiUnprotect
)

func sealString(s string) string {
	if s == "" || strings.HasPrefix(s, encPrefix) || protectFn == nil {
		return s
	}
	b, err := protectFn([]byte(s))
	if err != nil {
		log.Printf("dpapi protect: %v", err)
		return s
	}
	return encPrefix + base64.StdEncoding.EncodeToString(b)
}

// secretsUnreadable is set when a stored secret could not be decrypted (settings made by another Windows user, a
// reinstalled system, a folder copied to another PC). The values then read as empty, and the next save would erase
// them for good, so saveSettings keeps a copy of the old file first.
var secretsUnreadable atomic.Bool

func openString(s string) string {
	if !strings.HasPrefix(s, encPrefix) {
		return s
	}
	raw, err := base64.StdEncoding.DecodeString(s[len(encPrefix):])
	if err != nil || unprotectFn == nil {
		secretsUnreadable.Store(true)
		return ""
	}
	b, err := unprotectFn(raw)
	if err != nil {
		log.Printf("dpapi unprotect: %v (настройки зашифрованы под другим пользователем Windows?)", err)
		secretsUnreadable.Store(true)
		return ""
	}
	return string(b)
}

const unreadableBackup = "settings.unreadable.json"

// backupUnreadable keeps the first copy of a settings file whose secrets we could not read.
func backupUnreadable(dir string) {
	dst := filepath.Join(dir, unreadableBackup)
	if _, err := os.Stat(dst); err == nil {
		return
	}
	b, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil || !bytes.Contains(b, []byte(encPrefix)) {
		return
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		log.Printf("backup unreadable settings: %v", err)
		return
	}
	log.Printf("настройки не удалось расшифровать, старый файл сохранён как %s", unreadableBackup)
}

// secretsLostFor reports that the active server lost its credentials because they could not be decrypted.
func secretsLostFor(s Server) bool {
	return secretsUnreadable.Load() && s.Host != "" && s.UUID == "" && s.Password == ""
}

func mapServerSecrets(s *Server, f func(string) string) {
	s.Password, s.ObfsPassword, s.UUID = f(s.Password), f(s.ObfsPassword), f(s.UUID)
}

// mapSecrets applies f to every secret field. Profiles must already be an owned slice.
func mapSecrets(s *Settings, f func(string) string) {
	mapServerSecrets(&s.Server, f)
	for i := range s.Profiles {
		mapServerSecrets(&s.Profiles[i], f)
	}
	s.APISecret = f(s.APISecret)
	s.SubURL = f(s.SubURL)
	s.AppToken = f(s.AppToken)
}
