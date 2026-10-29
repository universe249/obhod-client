package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Сквозная проверка встроенного ядра: собираем программу, запускаем её с -core как это делает окно,
// ядро открывает порт, по закрытию stdin мягко завершается. Плюс version и check (в том числе ошибка в конфиге).
func TestEmbeddedCoreProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("сборка программы")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "app")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	tags, _ := os.ReadFile("CORE_TAGS")
	if out, err := exec.Command("go", "build", "-tags", strings.TrimSpace(string(tags)), "-ldflags=-checklinkname=0", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, coreFlag, "version").Output()
	if err != nil || !strings.HasPrefix(string(out), "sing-box 1.") {
		t.Fatalf("version %v %q", err, out)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfg := `{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":` + itoa(port) + `}],
		"outbounds":[{"type":"direct","tag":"direct"}],
		"experimental":{"clash_api":{"external_controller":"127.0.0.1:0"}}}`
	cp := filepath.Join(dir, "config.json")
	_ = os.WriteFile(cp, []byte(cfg), 0o600)
	if out, err := exec.Command(bin, coreFlag, "check", "-c", cp, "-D", dir).CombinedOutput(); err != nil {
		t.Fatalf("check: %v %s", err, out)
	}
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"outbounds":[{"type":"nope"}]}`), 0o600)
	if out, err := exec.Command(bin, coreFlag, "check", "-c", bad, "-D", dir).CombinedOutput(); err == nil || !strings.Contains(string(out), "nope") {
		t.Fatalf("bad config passed: %v %s", err, out)
	}

	cmd := exec.Command(bin, coreFlag, "run", "-c", cp, "-D", dir)
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	stdin, _ := cmd.StdinPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	up := false
	for i := 0; i < 50 && !up; i++ {
		if c, err := net.DialTimeout("tcp", "127.0.0.1:"+itoa(port), 200*time.Millisecond); err == nil {
			c.Close()
			up = true
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !up {
		cmd.Process.Kill()
		t.Fatalf("ядро не открыло порт: %s", log.String())
	}
	stdin.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("exit %v: %s", err, log.String())
		}
	case <-time.After(8 * time.Second):
		cmd.Process.Kill()
		t.Fatal("ядро не остановилось после закрытия stdin")
	}
}

func TestRemoveLegacyCore(t *testing.T) {
	dir := t.TempDir()
	exe, _ := os.Executable()
	bak := exe + ".bak"
	_ = os.Remove(bak)
	put := func() { _ = os.WriteFile(filepath.Join(dir, "sing-box.exe"), []byte("x"), 0o600) }
	has := func() bool { _, err := os.Stat(filepath.Join(dir, "sing-box.exe")); return err == nil }
	put()
	removeLegacyCore(dir) // отката нет — удаляем сразу
	if has() {
		t.Fatal("not removed")
	}
	put()
	_ = os.WriteFile(bak, []byte("old"), 0o600)
	defer os.Remove(bak)
	removeLegacyCore(dir)
	removeLegacyCore(dir)
	if !has() {
		t.Fatal("removed while rollback copy may need it")
	}
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(bak, future, future) // следующее обновление заменило .bak
	removeLegacyCore(dir)
	if has() {
		t.Fatal("not removed after .bak changed")
	}
}
