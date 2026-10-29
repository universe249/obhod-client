// release: подписывает сборку для автообновления.
//
//	release keygen                      — создать ключ (signing.key) и вывести публичную часть
//	release sign Obhod-v3.5.zip 3.5     — создать manifest.json и manifest.json.sig рядом с архивом
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		die("использование: release keygen | release sign <архив.zip> <версия> [signing.key]")
	}
	switch os.Args[1] {
	case "keygen":
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		if err := os.WriteFile("signing.key", []byte(base64.StdEncoding.EncodeToString(priv.Seed())), 0o600); err != nil {
			die("%v", err)
		}
		fmt.Println("Ключ записан в signing.key. НИКОМУ ЕГО НЕ ОТДАВАЙ и не выкладывай на GitHub.")
		fmt.Println("Публичная часть:", base64.StdEncoding.EncodeToString(pub))
	case "sign":
		if len(os.Args) < 4 {
			die("использование: release sign <архив.zip> <версия> [signing.key]")
		}
		zipPath, ver := os.Args[2], strings.TrimPrefix(os.Args[3], "v")
		keyPath := "signing.key"
		if len(os.Args) > 4 {
			keyPath = os.Args[4]
		}
		kb, err := os.ReadFile(keyPath)
		if err != nil {
			die("нет ключа: %v", err)
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(kb)))
		if err != nil || len(seed) != ed25519.SeedSize {
			die("ключ повреждён")
		}
		priv := ed25519.NewKeyFromSeed(seed)
		data, err := os.ReadFile(zipPath)
		if err != nil {
			die("%v", err)
		}
		sum := sha256.Sum256(data)
		man, _ := json.MarshalIndent(map[string]any{
			"version": ver, "file": filepath.Base(zipPath), "sha256": hex.EncodeToString(sum[:]), "size": len(data),
		}, "", "  ")
		dir := filepath.Dir(zipPath)
		os.WriteFile(filepath.Join(dir, "manifest.json"), man, 0o644)
		sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, man))
		os.WriteFile(filepath.Join(dir, "manifest.json.sig"), []byte(sig), 0o644)
		fmt.Println("Готово. Загрузи в релиз GitHub три файла:", filepath.Base(zipPath), "manifest.json manifest.json.sig")
	default:
		die("неизвестная команда")
	}
}
