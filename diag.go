package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type diagStep struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Info string `json:"info"`
}

type diagResult struct {
	Host    string     `json:"host"`
	Steps   []diagStep `json:"steps"`
	Route   string     `json:"route"` // proxy | direct | ""
	Rule    string     `json:"rule"`
	Level   string     `json:"level"` // ok | warn | bad
	Verdict string     `json:"verdict"`
	Suggest string     `json:"suggest"` // proxy | direct | ""
}

var delayClient = &http.Client{Timeout: 14 * time.Second}

// clashDelay asks sing-box to fetch testURL through the given outbound.
func clashDelay(st Settings, outbound, testURL string) (int, error) {
	q := "/proxies/" + url.PathEscape(outbound) + "/delay?timeout=9000&url=" + url.QueryEscape(testURL)
	req, _ := http.NewRequest("GET", "http://127.0.0.1:"+itoa(st.APIPort)+q, nil)
	req.Header.Set("Authorization", "Bearer "+st.APISecret)
	resp, err := delayClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var out struct {
		Delay   int    `json:"delay"`
		Message string `json:"message"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 200 {
		msg := out.Message
		if msg == "" {
			msg = fmt.Sprintf("код %d", resp.StatusCode)
		}
		return 0, fmt.Errorf("%s", msg)
	}
	return out.Delay, nil
}

// parseTarget turns "instagram.com", "https://x.com/a", "host:8443" into host and URL.
func parseTarget(in string) (host, rawURL string, err error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", "", fmt.Errorf("введи адрес сайта")
	}
	if !strings.Contains(in, "://") {
		in = "https://" + in
	}
	u, err := url.Parse(in)
	if err != nil || u.Hostname() == "" {
		return "", "", fmt.Errorf("не удалось разобрать адрес")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return strings.ToLower(u.Hostname()), u.String(), nil
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i < 80 {
		s = s[i+2:]
	}
	return s
}

func (a *App) diagnose(target string) (*diagResult, error) {
	host, rawURL, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	st := a.settings()
	res := &diagResult{Host: host}
	add := func(name string, ok bool, info string) { res.Steps = append(res.Steps, diagStep{name, ok, info}) }

	// 1. DNS as the provider's resolver answers
	dnsOK := false
	if net.ParseIP(host) != nil {
		add("Адрес", true, host)
		dnsOK = true
	} else {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(st.DNSLocal, "53"))
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		ips, err := r.LookupHost(ctx, host)
		cancel()
		if err != nil || len(ips) == 0 {
			add("DNS ("+st.DNSLocal+")", false, "адрес не находится или подменён провайдером")
		} else {
			if len(ips) > 3 {
				ips = ips[:3]
			}
			dnsOK = true
			add("DNS ("+st.DNSLocal+")", true, strings.Join(ips, ", "))
		}
	}

	running, _, _, _, _ := a.core.Info()
	ready := false
	if running {
		var cn struct{}
		ready = clashGet(st, "/connections", &cn) == nil
	}

	// 2. a normal request from this program (goes through the tunnel when it is on); watch which route it takes
	var mu sync.Mutex
	route, rule := "", ""
	stop := make(chan struct{})
	done := make(chan struct{})
	if ready {
		go func() {
			defer close(done)
			for {
				var cn struct {
					Connections []struct {
						Metadata struct {
							Host   string `json:"host"`
							DestIP string `json:"destinationIP"`
						} `json:"metadata"`
						Chains  []string `json:"chains"`
						Rule    string   `json:"rule"`
						Payload string   `json:"rulePayload"`
					} `json:"connections"`
				}
				if clashGet(st, "/connections", &cn) == nil {
					for _, c := range cn.Connections {
						h := strings.ToLower(c.Metadata.Host)
						if h == host || (h == "" && c.Metadata.DestIP == host) {
							mu.Lock()
							route = "direct"
							if len(c.Chains) > 0 && c.Chains[0] != "direct" {
								route = "proxy"
							}
							rule = strings.TrimSpace(c.Rule + " " + c.Payload)
							mu.Unlock()
						}
					}
				}
				select {
				case <-stop:
					return
				case <-time.After(80 * time.Millisecond):
				}
			}
		}()
	} else {
		close(done)
	}

	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t0 := time.Now()
	appOK := false
	req, _ := http.NewRequest("GET", rawURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, reqErr := client.Do(req)
	if reqErr == nil {
		appOK = true
		time.Sleep(350 * time.Millisecond) // let the connection show up in the list
		resp.Body.Close()
	}
	close(stop)
	<-done
	label := "Запрос от программы (как у любого приложения)"
	if !ready {
		label = "Прямой запрос (туннель выключен)"
	}
	if appOK {
		add(label, true, fmt.Sprintf("ответ %d за %d мс", resp.StatusCode, time.Since(t0).Milliseconds()-350))
	} else {
		add(label, false, shortErr(reqErr))
	}
	mu.Lock()
	res.Route, res.Rule = route, rule
	mu.Unlock()
	if ready {
		switch res.Route {
		case "proxy":
			add("Маршрут", true, "через сервер"+ruleSuffix(res.Rule))
		case "direct":
			add("Маршрут", true, "напрямую"+ruleSuffix(res.Rule))
		default:
			add("Маршрут", false, "соединение не успело показаться в списке")
		}
	}

	// 3. forced tests through each path
	proxyOK, directOK := false, false
	proxyKnown := false
	if ready {
		proxyKnown = true
		if ms, err := clashDelay(st, "proxy", rawURL); err == nil {
			proxyOK = true
			add("Принудительно через сервер", true, fmt.Sprintf("%d мс", ms))
		} else {
			add("Принудительно через сервер", false, shortErr(err))
		}
		if ms, err := clashDelay(st, "direct", rawURL); err == nil {
			directOK = true
			add("Принудительно напрямую", true, fmt.Sprintf("%d мс", ms))
		} else {
			add("Принудительно напрямую", false, shortErr(err))
		}
	} else {
		directOK = appOK
	}

	// 4. verdict
	switch {
	case !running:
		res.Level = "warn"
		if appOK {
			res.Verdict = "Туннель выключен. Сайт сейчас открывается напрямую. Включи туннель, если он нужен через сервер."
		} else {
			res.Verdict = "Туннель выключен, и напрямую сайт не открывается. Включи туннель и проверь ещё раз."
		}
	case !ready:
		res.Level = "warn"
		res.Verdict = "Туннель ещё запускается. Подожди несколько секунд и повтори."
	case !dnsOK && !proxyOK && !directOK:
		res.Level = "bad"
		res.Verdict = "Такого адреса нет или он недоступен ни напрямую, ни через сервер. Проверь, правильно ли написан адрес."
	case res.Route == "proxy" && appOK:
		res.Level = "ok"
		res.Verdict = "Работает через сервер."
	case res.Route == "" && appOK:
		res.Level = "ok"
		res.Verdict = "Сайт открывается. Каким путём он пошёл, определить не удалось: соединение слишком быстро закрылось."
	case res.Route == "direct" && appOK && !proxyKnown:
		res.Level = "ok"
		res.Verdict = "Открывается напрямую."
	case res.Route == "direct" && appOK:
		res.Level = "ok"
		res.Verdict = "Открывается напрямую, сервер не нужен."
	case res.Route == "direct" && !appOK && proxyOK:
		res.Level = "bad"
		res.Verdict = "Сайт заблокирован: напрямую он не открывается, но через сервер открывается. Его нет в списках, добавь в «через сервер»."
		res.Suggest = "proxy"
	case res.Route == "proxy" && !appOK && directOK:
		res.Level = "bad"
		res.Verdict = "Через сервер сайт не открывается, а напрямую открывается. Лучше пускать его напрямую."
		res.Suggest = "direct"
	case res.Route == "proxy" && !appOK && !proxyOK:
		res.Level = "bad"
		res.Verdict = "Идёт через сервер, но не открывается. Сервер не может его загрузить или туннель работает плохо. Нажми «Проверить связь» на главной; если не поможет — отправь отчёт администратору в «Помощи»."
	case !appOK && proxyOK && !directOK:
		res.Level = "bad"
		res.Verdict = "Напрямую недоступен, через сервер доступен. Добавь в «через сервер»."
		res.Suggest = "proxy"
	case !appOK && !proxyOK && !directOK:
		res.Level = "bad"
		res.Verdict = "Не открывается ни напрямую, ни через сервер. Скорее всего, проблема в самом сайте, а не в обходе."
	default:
		res.Level = "warn"
		res.Verdict = "Результаты неоднозначные, смотри шаги выше."
	}
	return res, nil
}

func ruleSuffix(rule string) string {
	if rule == "" {
		return ""
	}
	return " (правило: " + rule + ")"
}

// handleDiagnose runs a check; handleDiagnoseAdd puts a host into one of the user lists.
func (a *App) handleDiagnose(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	res, err := a.diagnose(in.Target)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (a *App) handleDiagnoseAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host string `json:"host"`
		Mode string `json:"mode"` // proxy | direct
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	host := normDomain(in.Host)
	if host == "" {
		fail(w, 400, "пустой адрес")
		return
	}
	a.mu.Lock()
	switch in.Mode {
	case "proxy":
		a.st.CustomDomains = uniq(append(a.st.CustomDomains, host))
		a.st.DirectDomains = removeStr(a.st.DirectDomains, host)
	case "direct":
		a.st.DirectDomains = uniq(append(a.st.DirectDomains, host))
		a.st.CustomDomains = removeStr(a.st.CustomDomains, host)
	default:
		a.mu.Unlock()
		fail(w, 400, "неизвестный режим")
		return
	}
	st := a.st
	a.mu.Unlock()
	if err := saveSettings(a.dataDir, st); err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "customDomains": st.CustomDomains, "directDomains": st.DirectDomains})
}

func removeStr(in []string, v string) []string {
	var out []string
	for _, x := range in {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}
