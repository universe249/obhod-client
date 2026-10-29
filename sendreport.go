package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultReportURL is where the Telegram bot accepts diagnostics (POST /report?code=...).
const defaultReportURL = "http://hoop.un1v249.ru:8788/report"

// defaultReportURLTLS is the same endpoint behind Caddy (HTTPS). The zip holds settings and rules, so it is tried first;
// plain HTTP stays only as a fallback when the HTTPS port cannot be reached.
const defaultReportURLTLS = "https://hoop.un1v249.ru:8444/report"

// sendReport builds the diagnostic zip and uploads it to the bot with the one-time code the user got from it.
func (a *App) sendReport(code string) error {
	code = strings.TrimSpace(code)
	if code == "" {
		return fmt.Errorf("введи код из бота")
	}
	bases := []string{a.settings().ReportURL}
	if bases[0] == "" {
		bases = []string{defaultReportURLTLS, defaultReportURL}
	}
	var buf bytes.Buffer
	a.writeReport(&buf)
	var resp *http.Response
	var err error
	for _, base := range bases {
		u := base + "?code=" + url.QueryEscape(code) + "&v=" + url.QueryEscape(appVersion)
		req, e := http.NewRequest("POST", u, bytes.NewReader(buf.Bytes()))
		if e != nil {
			return e
		}
		req.Header.Set("Content-Type", "application/zip")
		resp, err = (&http.Client{Timeout: 40 * time.Second}).Do(req)
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("не удалось связаться с ботом: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	switch resp.StatusCode {
	case 200:
		return nil
	case 403:
		return fmt.Errorf("код не подошёл или устарел — возьми новый в боте")
	default:
		return fmt.Errorf("бот ответил %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
}

func (a *App) handleSendReport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if err := a.sendReport(in.Code); err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
