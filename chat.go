package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type chatMsg struct {
	ID   int    `json:"id"`
	Dir  string `json:"dir"` // in — от человека, out — ответ поддержки
	Text string `json:"text"`
	TS   int64  `json:"ts"`
}

var errNoChat = errors.New("войди через Telegram (вкладка «Подключение»), чтобы писать в поддержку из программы")

// chatCall: запрос к боту с токеном приложения. Только HTTPS: в переписке может быть личное.
func (a *App) chatCall(method, path string, body io.Reader, ctype string, out any) error {
	tok := a.settings().AppToken
	if tok == "" {
		return errNoChat
	}
	req, err := http.NewRequest(method, loginBase+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-App-Token", tok)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("бот недоступен: %v", err)
	}
	defer resp.Body.Close()
	var e struct {
		Error string `json:"error"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == 401 {
		return errNoChat
	}
	if resp.StatusCode != 200 {
		_ = json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("бот ответил %d", resp.StatusCode)
		}
		return errors.New(e.Error)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (a *App) chatList(since int) ([]chatMsg, error) {
	var out struct {
		Messages []chatMsg `json:"messages"`
	}
	err := a.chatCall("GET", "/app/chat/list?since="+strconv.Itoa(since), nil, "", &out)
	return out.Messages, err
}

// POST /api/chat {action: list|send, text, report}
func (a *App) handleChat(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string `json:"action"`
		Text   string `json:"text"`
		Report bool   `json:"report"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный запрос")
		return
	}
	switch in.Action {
	case "list":
		msgs, err := a.chatList(0)
		if err != nil {
			fail(w, 502, err.Error())
			return
		}
		a.markChatSeen(msgs)
		writeJSON(w, 200, map[string]any{"messages": msgs})
	case "send":
		text := strings.TrimSpace(in.Text)
		if text == "" {
			fail(w, 400, "напиши, что случилось")
			return
		}
		if len([]rune(text)) > 1500 {
			text = string([]rune(text)[:1500])
		}
		b, _ := json.Marshal(map[string]string{"text": text})
		if err := a.chatCall("POST", "/app/chat/send", bytes.NewReader(b), "application/json", nil); err != nil {
			fail(w, 502, err.Error())
			return
		}
		if in.Report { // отчёт без паролей и ключей, тот же, что «Отправить отчёт администратору»
			var buf bytes.Buffer
			a.writeReport(&buf)
			if err := a.chatCall("POST", "/app/chat/report?v="+url.QueryEscape(appVersion), &buf, "application/zip", nil); err != nil {
				writeJSON(w, 200, map[string]any{"ok": true, "note": "сообщение ушло, а отчёт нет: " + err.Error()})
				return
			}
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	default:
		fail(w, 400, "неизвестное действие")
	}
}

func (a *App) markChatSeen(msgs []chatMsg) {
	last := 0
	for _, m := range msgs {
		if m.ID > last {
			last = m.ID
		}
	}
	a.chatUnread.Store(0)
	a.mu.Lock()
	changed := last > a.st.ChatSeen
	if changed {
		a.st.ChatSeen = last
	}
	st := a.st
	a.mu.Unlock()
	if changed {
		_ = saveSettings(a.dataDir, st)
	}
}

// chatLoop: раз в 3 минуты проверяет ответы поддержки и показывает уведомление Windows о новом.
func (a *App) chatLoop() {
	for {
		select {
		case <-a.quit:
			return
		case <-time.After(3 * time.Minute):
		}
		st := a.settings()
		if st.AppToken == "" {
			continue
		}
		msgs, err := a.chatList(st.ChatSeen)
		if err != nil {
			continue
		}
		n := 0
		var lastText string
		for _, m := range msgs {
			if m.Dir == "out" && m.ID > st.ChatSeen {
				n++
				lastText = m.Text
			}
		}
		if n > 0 && int(a.chatUnread.Load()) < n {
			a.chatUnread.Store(int32(n))
			t := []rune(lastText)
			if len(t) > 120 {
				t = append(t[:120], '…')
			}
			a.notify("Ответ поддержки", string(t))
		}
	}
}
