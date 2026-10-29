package main

import (
	"testing"
	"time"
)

// startTrace не должен ронять процесс (раньше затирал занятый мьютекс и падал с «unlock of unlocked mutex»).
func TestStartTraceDoesNotCrash(t *testing.T) {
	a := &App{dataDir: t.TempDir(), core: &Core{}, quit: make(chan struct{})}
	if err := a.startTrace("127.0.0.1", 0, false); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if !a.trace.snapshot()["running"].(bool) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if a.trace.snapshot()["host"] != "127.0.0.1" {
		t.Fatalf("%v", a.trace.snapshot())
	}
	// повторный запуск после окончания
	if err := a.startTrace("127.0.0.1", 0, false); err != nil {
		t.Fatal(err)
	}
}
