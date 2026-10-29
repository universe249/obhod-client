package main

import (
	"os"
	"strings"
	"testing"
)

// Название системной библиотеки не должно портиться при переименовании переменных (так в 6.0.1–6.0.7 вышла паника «wvDwmDLL.dll»).
func TestDwmLibraryName(t *testing.T) {
	b, err := os.ReadFile("webwin_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"dwmapi.dll"`) || strings.Contains(string(b), `Dll.dll`) || strings.Contains(string(b), `DLL.dll"`) {
		t.Fatal("имя dwmapi.dll испорчено")
	}
}
