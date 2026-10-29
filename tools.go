package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- route trace to the server ----------

type Hop struct {
	N  int    `json:"n"`
	IP string `json:"ip"`
	Ms int    `json:"ms"` // -1 = no answer
}

var hopRe = regexp.MustCompile(`^\s*(\d{1,2})\s+(.*)$`)
var msRe = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*ms`)
var ipRe = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)

// parseHop reads one line of tracert / traceroute output.
func parseHop(line string) (Hop, bool) {
	m := hopRe.FindStringSubmatch(line)
	if m == nil {
		return Hop{}, false
	}
	n, _ := strconv.Atoi(m[1])
	rest := m[2]
	h := Hop{N: n, Ms: -1}
	var sum float64
	var cnt int
	for _, x := range msRe.FindAllStringSubmatch(rest, -1) {
		v, _ := strconv.ParseFloat(x[1], 64)
		sum += v
		cnt++
	}
	if strings.Contains(rest, "<1 ms") && cnt == 0 {
		cnt = 1
	}
	if cnt > 0 {
		h.Ms = int(sum/float64(cnt) + 0.5)
	}
	// the answering address is the last IPv4 on the line
	if all := ipRe.FindAllString(rest, -1); len(all) > 0 {
		h.IP = all[len(all)-1]
	}
	if h.IP == "" && h.Ms < 0 && !strings.Contains(rest, "*") {
		return Hop{}, false
	}
	return h, true
}

// traceVerdict explains the result in plain words.
func traceVerdict(hops []Hop, targetIP string, tcpTried, tcpOK bool, tcpMs, port int) (level, text string) {
	reached := false
	last := -1
	for i, h := range hops {
		if h.IP != "" && h.Ms >= 0 {
			last = i
		}
		if h.IP == targetIP {
			reached = true
		}
	}
	switch {
	case tcpTried && tcpOK:
		t := fmt.Sprintf("Сервер доступен: порт %d отвечает за %d мс.", port, tcpMs)
		if !reached {
			t += " Трассировка не дошла до конца, но это нормально: многие серверы не отвечают на ICMP."
		}
		return "ok", t
	case !tcpTried && reached:
		return "ok", "Трассировка дошла до сервера."
	case last < 0:
		return "bad", "Нет ответа даже от первого узла. Проверь, что компьютер подключён к роутеру и интернету."
	}
	h := hops[last]
	where := "дальше по пути (у хостера или на магистрали)"
	if h.N <= 2 {
		where = "рядом с тобой (роутер или оборудование провайдера)"
	} else if h.N <= 4 {
		where = "у твоего провайдера"
	}
	t := fmt.Sprintf("Пакеты доходят до узла №%d (%s), дальше тишина — это %s.", h.N, h.IP, where)
	if tcpTried {
		t += fmt.Sprintf(" Порт %d тоже не отвечает.", port)
	}
	t += " Если сервер при этом работает у других, попробуй другой протокол или порт, либо напиши провайдеру."
	return "bad", t
}

type traceState struct {
	mu      sync.Mutex
	running bool
	host    string
	ip      string
	hops    []Hop
	done    bool
	err     string
	level   string
	verdict string
	cancel  context.CancelFunc
}

func (t *traceState) snapshot() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	return map[string]any{"running": t.running, "host": t.host, "ip": t.ip, "hops": append([]Hop(nil), t.hops...),
		"done": t.done, "error": t.err, "level": t.level, "verdict": t.verdict}
}

func traceCommand(ctx context.Context, host string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		c := exec.CommandContext(ctx, "tracert", "-d", "-h", "18", "-w", "1200", host)
		hide(c)
		return c
	}
	return exec.CommandContext(ctx, "traceroute", "-n", "-m", "18", "-w", "1", host)
}

func (a *App) startTrace(host string, port int, udp bool) error {
	t := &a.trace
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return errors.New("проверка уже идёт")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	t.running, t.done, t.host, t.ip, t.hops, t.err, t.level, t.verdict, t.cancel = true, false, host, "", nil, "", "", "", cancel
	t.mu.Unlock()
	go func() {
		defer cancel()
		fin := func(err string) {
			t.mu.Lock()
			t.running, t.done, t.err = false, true, err
			t.mu.Unlock()
		}
		ips, err := net.LookupHost(host)
		if err != nil || len(ips) == 0 {
			fin("не удалось определить адрес «" + host + "»")
			return
		}
		ip := ips[0]
		for _, c := range ips {
			if net.ParseIP(c) != nil && net.ParseIP(c).To4() != nil {
				ip = c
				break
			}
		}
		t.mu.Lock()
		t.ip = ip
		t.mu.Unlock()
		cmd := traceCommand(ctx, ip)
		out, err := cmd.StdoutPipe()
		if err != nil {
			fin(err.Error())
			return
		}
		if err := cmd.Start(); err != nil {
			fin("не удалось запустить трассировку: " + err.Error())
			return
		}
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if h, ok := parseHop(sc.Text()); ok {
				t.mu.Lock()
				t.hops = append(t.hops, h)
				t.mu.Unlock()
			}
		}
		_ = cmd.Wait()
		tcpTried, tcpOK, ms := false, false, 0
		if port > 0 && !udp {
			tcpTried = true
			t0 := time.Now()
			c, e := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 4*time.Second)
			if e == nil {
				tcpOK, ms = true, int(time.Since(t0).Milliseconds())
				c.Close()
			}
		}
		t.mu.Lock()
		hops := append([]Hop(nil), t.hops...)
		t.mu.Unlock()
		lv, text := traceVerdict(hops, ip, tcpTried, tcpOK, ms, port)
		if udp {
			text += " (Hysteria2 работает по UDP, порт здесь проверить нельзя.)"
		}
		t.mu.Lock()
		t.running, t.done, t.level, t.verdict = false, true, lv, text
		t.mu.Unlock()
	}()
	return nil
}

func (a *App) handleTrace(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, 200, a.trace.snapshot())
		return
	}
	var in struct {
		Action string `json:"action"`
		Host   string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, "неверный JSON")
		return
	}
	if in.Action == "stop" {
		a.trace.mu.Lock()
		if a.trace.cancel != nil {
			a.trace.cancel()
		}
		a.trace.mu.Unlock()
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if a.core.Running() {
		fail(w, 409, "Выключи обход на время проверки: при включённом туннеле пакеты идут через него, и путь будет показан неверно.")
		return
	}
	st := a.settings()
	host, port, udp := strings.TrimSpace(in.Host), 0, false
	if host == "" {
		host, port, udp = st.Server.Host, st.Server.Port, st.Server.Type == "hysteria2"
	}
	host = normDomain(host)
	if host == "" || strings.ContainsAny(host, " \t\"';|&<>") {
		fail(w, 400, "укажи адрес сервера или сайта")
		return
	}
	if err := a.startTrace(host, port, udp); err != nil {
		fail(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------- DNS check ----------

type dnsCand struct {
	Name, Addr, Kind string // Kind: system | udp | doh
}

var dnsCands = []dnsCand{
	{"Как сейчас (DNS системы)", "", "system"},
	{"Яндекс DNS", "77.88.8.8", "udp"},
	{"Cloudflare", "1.1.1.1", "udp"},
	{"Google", "8.8.8.8", "udp"},
	{"Quad9", "9.9.9.9", "udp"},
	{"Cloudflare, шифрованный (DoH)", "cloudflare", "doh"},
	{"Google, шифрованный (DoH)", "google", "doh"},
}

var dnsNames = []string{"ya.ru", "vk.com", "wikipedia.org", "discord.com", "instagram.com", "youtube.com"}

type DNSResult struct {
	Name  string `json:"name"`
	Addr  string `json:"addr"`
	Kind  string `json:"kind"`
	OK    int    `json:"ok"`
	Total int    `json:"total"`
	Ms    int    `json:"ms"` // average of successful lookups, -1 if none
	Stub  int    `json:"stub"`
	Note  string `json:"note,omitempty"`
	Best  bool   `json:"best,omitempty"`
}

// isStubIP is an address a resolver gives instead of the real one when it blocks or fakes a name.
func isStubIP(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast()
}

// dnsPick returns the index of the best resolver: everything resolves, nothing is faked, lowest latency.
func dnsPick(rs []DNSResult) int {
	best := -1
	for i, r := range rs {
		if r.Kind == "system" || r.OK < r.Total || r.Stub > 0 || r.Ms < 0 {
			continue
		}
		if best < 0 || r.Ms < rs[best].Ms {
			best = i
		}
	}
	return best
}

func lookupUDP(addr, name string) ([]net.IP, error) {
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", net.JoinHostPort(addr, "53"))
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	ips, err := res.LookupIP(ctx, "ip4", name)
	return ips, err
}

func lookupSystem(name string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	return net.DefaultResolver.LookupIP(ctx, "ip4", name)
}

var dohClient = &http.Client{Timeout: 3 * time.Second}

func lookupDoH(kind, name string) ([]net.IP, error) {
	var u string
	if kind == "google" {
		u = "https://8.8.8.8/resolve?type=A&name=" + url.QueryEscape(name)
	} else {
		u = "https://1.1.1.1/dns-query?type=A&name=" + url.QueryEscape(name)
	}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Accept", "application/dns-json")
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var j struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, a := range j.Answer {
		if a.Type == 1 {
			if ip := net.ParseIP(a.Data); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("пустой ответ")
	}
	return ips, nil
}

func runDNSCheck() []DNSResult {
	out := make([]DNSResult, len(dnsCands))
	var wg sync.WaitGroup
	for i, c := range dnsCands {
		wg.Add(1)
		go func(i int, c dnsCand) {
			defer wg.Done()
			r := DNSResult{Name: c.Name, Addr: c.Addr, Kind: c.Kind, Total: len(dnsNames), Ms: -1}
			var sum, n int
			for k, name := range dnsNames {
				t0 := time.Now()
				var ips []net.IP
				var err error
				switch c.Kind {
				case "system":
					ips, err = lookupSystem(name)
				case "doh":
					ips, err = lookupDoH(c.Addr, name)
				default:
					ips, err = lookupUDP(c.Addr, name)
				}
				ms := int(time.Since(t0).Milliseconds())
				if err != nil || len(ips) == 0 {
					if r.Note == "" {
						r.Note = "не ответил на «" + name + "»"
					}
					continue
				}
				r.OK++
				for _, ip := range ips {
					if isStubIP(ip) {
						r.Stub++
						if r.Note == "" {
							r.Note = "«" + name + "» → " + ip.String() + " (заглушка)"
						}
						break
					}
				}
				if c.Kind == "doh" && k == 0 {
					continue // the first request pays for the TLS handshake
				}
				sum += ms
				n++
			}
			if n > 0 {
				r.Ms = sum / n
			}
			out[i] = r
		}(i, c)
	}
	wg.Wait()
	if b := dnsPick(out); b >= 0 {
		out[b].Best = true
	}
	return out
}

func dnsAdvice(rs []DNSResult) string {
	var sys *DNSResult
	for i := range rs {
		if rs[i].Kind == "system" {
			sys = &rs[i]
		}
	}
	b := dnsPick(rs)
	if b < 0 {
		return "Ни один DNS не ответил на все имена. Проверь подключение к интернету."
	}
	t := "Лучший по скорости и честности ответов: " + rs[b].Name + " (" + strconv.Itoa(rs[b].Ms) + " мс)."
	if sys != nil && sys.Stub > 0 {
		t += " Твой текущий DNS возвращает заглушки вместо настоящих адресов: провайдер подменяет ответы. Лучше перейти на шифрованный DNS."
	} else if sys != nil && sys.OK < sys.Total {
		t += " Текущий DNS отвечает не на все имена."
	}
	return t
}

func (a *App) handleDNSCheck(w http.ResponseWriter, r *http.Request) {
	if a.core.Running() {
		fail(w, 409, "Выключи обход на время проверки: при включённом туннеле он перехватывает все DNS-запросы, и результаты будут неверными.")
		return
	}
	if !a.dnsBusy.CompareAndSwap(false, true) {
		fail(w, 409, "проверка уже идёт")
		return
	}
	defer a.dnsBusy.Store(false)
	rs := runDNSCheck()
	best := dnsPick(rs)
	apply := map[string]string{}
	if best >= 0 {
		apply["kind"], apply["value"] = rs[best].Kind, rs[best].Addr
	}
	writeJSON(w, 200, map[string]any{"results": rs, "advice": dnsAdvice(rs), "apply": apply})
}
