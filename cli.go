package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const cliHelp = `Использование: %s <команда>

  on                включить обход
  off               выключить обход
  status            состояние (код выхода 0 — включён и работает, 1 — выключен)
  servers           список сохранённых серверов
  use <№|имя>       переключиться на сервер
  ping              задержка через сервер, мс
  help              эта справка

Программа должна быть запущена (окно или значок в трее).`

var cliCommands = map[string]bool{"on": true, "off": true, "status": true, "servers": true, "use": true, "ping": true, "help": true}

func isCLI(args []string) bool { return len(args) > 0 && cliCommands[strings.ToLower(args[0])] }

type cliClient struct {
	base, token string
	hc          *http.Client
}

func newCLIClient(dataDir string) (*cliClient, error) {
	tb, err := os.ReadFile(filepath.Join(dataDir, "token"))
	if err != nil {
		return nil, fmt.Errorf("программа ещё ни разу не запускалась (нет %s)", filepath.Join(dataDir, "token"))
	}
	port := loadSettings(dataDir).UIPort
	return &cliClient{base: fmt.Sprintf("http://127.0.0.1:%d", port), token: strings.TrimSpace(string(tb)),
		hc: &http.Client{Timeout: 60 * time.Second}}, nil
}

func (c *cliClient) call(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else if method == http.MethodPost {
		rd = strings.NewReader("{}")
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.AddCookie(&http.Cookie{Name: "singui", Value: c.token})
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("программа не запущена — открой «%s» или дождись её запуска", appName)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var env struct {
		OK    *bool  `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	if resp.StatusCode >= 400 || (env.OK != nil && !*env.OK) {
		if env.Error != "" {
			return fmt.Errorf("%s", env.Error)
		}
		return fmt.Errorf("ошибка %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// runCLI executes a command and returns the process exit code.
func runCLI(args []string, dataDir string, stdout, stderr io.Writer) int {
	cmd := strings.ToLower(args[0])
	if cmd == "help" {
		fmt.Fprintf(stdout, cliHelp+"\n", appName)
		return 0
	}
	c, err := newCLIClient(dataDir)
	if err != nil {
		fmt.Fprintln(stderr, "Ошибка:", err)
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(stderr, "Ошибка:", err); return 2 }
	switch cmd {
	case "on", "off":
		path := "/api/core/start"
		if cmd == "off" {
			path = "/api/core/stop"
		}
		if err := c.call("POST", path, nil, nil); err != nil {
			return fail(err)
		}
		if cmd == "on" {
			fmt.Fprintln(stdout, "Обход включён")
		} else {
			fmt.Fprintln(stdout, "Обход выключен")
		}
	case "status":
		var s struct {
			Running    bool   `json:"running"`
			Health     string `json:"health"`
			PingMs     int    `json:"pingMs"`
			ServerName string `json:"serverName"`
			Version    string `json:"version"`
		}
		if err := c.call("GET", "/api/state", nil, &s); err != nil {
			return fail(err)
		}
		if !s.Running {
			fmt.Fprintf(stdout, "Выключен (сервер: %s, версия %s)\n", s.ServerName, s.Version)
			return 1
		}
		fmt.Fprintf(stdout, "Включён, сервер: %s, связь: %s, %d мс\n", s.ServerName, s.Health, s.PingMs)
	case "servers":
		var s struct {
			Profiles []struct {
				Name, Host string
				Protocol   string `json:"protocol"`
			} `json:"profiles"`
		}
		if err := c.call("GET", "/api/settings", nil, &s); err != nil {
			return fail(err)
		}
		if len(s.Profiles) == 0 {
			fmt.Fprintln(stdout, "Сохранённых серверов нет")
			return 0
		}
		for i, p := range s.Profiles {
			name := p.Name
			if name == "" {
				name = p.Host
			}
			fmt.Fprintf(stdout, "%d  %s  (%s)\n", i+1, name, p.Host)
		}
	case "use":
		if len(args) < 2 {
			return fail(fmt.Errorf("укажи номер или имя сервера: use <№|имя>"))
		}
		var s struct {
			Profiles []struct{ Name, Host string } `json:"profiles"`
		}
		if err := c.call("GET", "/api/settings", nil, &s); err != nil {
			return fail(err)
		}
		want := strings.TrimSpace(strings.Join(args[1:], " "))
		idx := -1
		if n, err := strconv.Atoi(want); err == nil && n >= 1 && n <= len(s.Profiles) {
			idx = n - 1
		} else {
			for i, p := range s.Profiles {
				if strings.EqualFold(p.Name, want) || strings.EqualFold(p.Host, want) {
					idx = i
					break
				}
			}
		}
		if idx < 0 {
			return fail(fmt.Errorf("сервер «%s» не найден (список: servers)", want))
		}
		if err := c.call("POST", "/api/profiles", map[string]any{"action": "use", "index": idx}, nil); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "Выбран сервер №%d\n", idx+1)
	case "ping":
		var r struct {
			Ms int `json:"ms"`
		}
		if err := c.call("GET", "/api/ping", nil, &r); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "%d мс\n", r.Ms)
	}
	return 0
}
