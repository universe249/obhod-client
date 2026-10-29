package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Радар блокировок. Журнал связи раз в минуту проверяет пути до сервера: напрямую, через ретрансляторы и
// «интернет вообще». Если прямой путь молчит 5 минут подряд, а интернет есть, значит, сервер недоступен именно
// из этой сети (так выглядела блокировка Хельсинки). Программа сообщает об этом боту — администратор узнаёт
// сразу, а не от пользователей. Отчёт уходит через туннель (он в этот момент работает через запасной путь).

const (
	radarAfter   = 5 * time.Minute
	radarRefresh = 30 * time.Minute
	pathDirect   = "напрямую"
	pathInternet = "интернет"
)

type radarState struct {
	State string   `json:"state"` // ok | main (прямой путь не работает, обходной есть) | all (не работает ни один путь)
	Since int64    `json:"since"`
	Via   []string `json:"via"` // какие пути работают
}

type radar struct {
	mu       sync.Mutex
	badSince time.Time
	cur      radarState
	sent     string
	sentAt   time.Time
}

func probeFailed(ms int) bool { return ms < 0 || ms >= 4000 }

// step обрабатывает очередную проверку журнала связи. send=true — пора отправить отчёт.
func (r *radar) step(res map[string]int, now time.Time) (st radarState, send bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	direct, ok := res[pathDirect]
	if !ok {
		return r.cur, false
	}
	if inet, ok := res[pathInternet]; ok && probeFailed(inet) {
		return r.cur, false // нет интернета вообще — о блокировке судить нельзя
	}
	var via []string
	for k, v := range res {
		if k != pathDirect && k != pathInternet && !probeFailed(v) {
			via = append(via, k)
		}
	}
	sort.Strings(via)
	if probeFailed(direct) {
		if r.badSince.IsZero() {
			r.badSince = now
		}
		if now.Sub(r.badSince) >= radarAfter {
			state := "all"
			if len(via) > 0 {
				state = "main"
			}
			r.cur = radarState{State: state, Since: r.badSince.Unix(), Via: via}
		}
	} else {
		r.badSince = time.Time{}
		r.cur = radarState{State: "ok", Via: via}
	}
	if r.cur.State == "" {
		return r.cur, false
	}
	changed := r.cur.State != r.sent && !(r.sent == "" && r.cur.State == "ok")
	stale := r.cur.State != "ok" && now.Sub(r.sentAt) >= radarRefresh
	return r.cur, changed || stale
}

func (r *radar) markSent(state string, now time.Time) {
	r.mu.Lock()
	r.sent, r.sentAt = state, now
	r.mu.Unlock()
}

// radarReport отправляет состояние боту (только пользователям нашего сервиса). Идёт через туннель.
func (a *App) radarReport(rs radarState) {
	st := a.settings()
	if !serviceOK(st) {
		return
	}
	tok := ""
	if st.SubURL != "" {
		if i := strings.LastIndex(st.SubURL, "/"); i >= 0 {
			tok = st.SubURL[i+1:]
		}
	}
	if st.AppToken == "" && !strings.HasPrefix(tok, "k") {
		return // бот не узнает, чей это отчёт
	}
	body, _ := json.Marshal(map[string]any{
		"state": rs.State, "since": rs.Since, "via": rs.Via, "server": st.Server.Name,
		"ver": appVersion, "os": runtime.GOOS, "sub": tok,
	})
	req, err := http.NewRequest("POST", loginBase+"/app/radar", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if st.AppToken != "" {
		req.Header.Set("X-App-Token", st.AppToken)
	}
	setDeviceHeaders(req)
	resp, err := probeClient(st, probeUserProxy, 20*time.Second).Do(req)
	if err != nil {
		log.Printf("радар: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		a.radar.markSent(rs.State, time.Now())
		if rs.State != "ok" {
			a.event("warn", "Сервер недоступен напрямую из твоей сети — администратору отправлено сообщение")
		}
	}
}
