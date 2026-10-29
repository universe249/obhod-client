package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// «Почему не работает»: идём по цепочке до сервера по шагам и говорим, на каком звене обрыв.
// Шаги: имя сервера → TCP-порт → TLS-рукопожатие → запрос через туннель.

type linkDiag struct {
	Server  string     `json:"server"`
	Steps   []diagStep `json:"steps"`
	Level   string     `json:"level"` // ok | warn | bad
	Verdict string     `json:"verdict"`
	Hint    string     `json:"hint"`
}

// linkProbe is what the steps return; injected in tests.
type linkProbe struct {
	DNS    func(host string) ([]string, error)
	TCP    func(addr string) error
	TLS    func(addr, sni string) error
	Tunnel func() (int, error) // ms
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)
}

func tcpErrText(err error) string {
	switch {
	case isTimeout(err):
		return "не отвечает (таймаут)"
	case strings.Contains(err.Error(), "refused"):
		return "порт закрыт"
	case strings.Contains(err.Error(), "unreachable"):
		return "сеть недоступна"
	}
	return shortErr(err)
}

func tlsErrText(err error) string {
	switch {
	case isTimeout(err):
		return "рукопожатие повисло"
	case strings.Contains(err.Error(), "reset"):
		return "соединение сброшено"
	case strings.Contains(err.Error(), "EOF"):
		return "соединение оборвано"
	}
	return shortErr(err)
}

// runLinkDiag does the steps for one server and picks the verdict from where the chain broke.
func runLinkDiag(sv Server, tunnelOn bool, p linkProbe) linkDiag {
	res := linkDiag{Server: serverKey(sv)}
	add := func(name string, ok bool, info string) { res.Steps = append(res.Steps, diagStep{name, ok, info}) }
	udp := sv.Type == "hysteria2"
	useTLS := !udp && (sv.Type == "vless" || sv.Type == "trojan") && (sv.Security == "tls" || sv.Security == "reality")
	sni := sv.SNI
	if sni == "" {
		sni = sv.Host
	}
	addr := net.JoinHostPort(sv.Host, itoa(sv.Port))

	// 1. имя
	if net.ParseIP(sv.Host) != nil {
		add("Адрес сервера", true, sv.Host)
	} else {
		ips, err := p.DNS(sv.Host)
		if err != nil || len(ips) == 0 {
			add("Имя сервера", false, "не находится: DNS провайдера не отвечает или подменяет адрес")
			res.Level, res.Verdict = "bad", "Не находится адрес сервера."
			res.Hint = "Включи шифрованный DNS («Подключение → Дополнительно → Шифрованный DNS (DoH)») или смени DNS на 1.1.1.1. Если сервер уже работал, возможно, домен заблокирован: тогда нужен адрес по IP."
			return res
		}
		if len(ips) > 3 {
			ips = ips[:3]
		}
		add("Имя сервера", true, strings.Join(ips, ", "))
	}

	// 2. TCP (UDP-протокол так не проверить)
	tcpOK := true
	if udp {
		add("Порт сервера", true, "UDP (Hysteria2): без ответа не проверить, смотрим сквозной запрос")
	} else if err := p.TCP(addr); err != nil {
		tcpOK = false
		add("Порт сервера", false, tcpErrText(err))
	} else {
		add("Порт сервера", true, "открывается")
	}

	// 3. TLS
	tlsOK := true
	if useTLS && tcpOK {
		if err := p.TLS(addr, sni); err != nil {
			tlsOK = false
			add("TLS-рукопожатие ("+sni+")", false, tlsErrText(err))
		} else {
			add("TLS-рукопожатие ("+sni+")", true, "проходит")
		}
	}

	// 4. сквозной запрос через туннель
	tunnelOK, tunnelTried := false, false
	if tunnelOn {
		tunnelTried = true
		ms, err := p.Tunnel()
		if err != nil {
			add("Запрос через туннель", false, shortErr(err))
		} else {
			tunnelOK = true
			add("Запрос через туннель", true, fmt.Sprintf("%d мс", ms))
		}
	}

	switch {
	case tunnelTried && tunnelOK:
		res.Level, res.Verdict = "ok", "Всё в порядке: туннель отвечает."
		if !tcpOK || !tlsOK {
			res.Level, res.Verdict = "warn", "Туннель отвечает, хотя прямая проверка порта не прошла."
			res.Hint = "Так бывает, когда сервер доступен только через само соединение (например, другой вход). Если всё открывается, можно не обращать внимания."
		}
	case !tcpOK:
		res.Level, res.Verdict = "bad", "Сервер недоступен с этого интернета."
		res.Hint = "Проверь, работает ли сервер у других (или спроси админа в боте). Если у других всё работает, провайдер режет этот адрес или порт: попробуй другой сервер, мобильную сеть или другой порт."
	case !tlsOK:
		res.Level, res.Verdict = "bad", "Порт открыт, но защищённое соединение не устанавливается."
		res.Hint = "Похоже на блокировку по рукопожатию. Включи «Фрагментацию TLS» и нажми «Подобрать способ» на вкладке «Подключение»: программа переберёт отпечатки и режимы."
	case tunnelTried && !tunnelOK:
		res.Level, res.Verdict = "bad", "До сервера дотягиваемся, но через туннель ничего не открывается."
		res.Hint = "Часто это неверные данные сервера (UUID, ключ, short id), сброшенные в панели ссылки или проблема на самом сервере. Обнови подписку, если пользуешься ею, и спроси админа."
	default:
		res.Level, res.Verdict = "warn", "До сервера дотягиваемся, но обход выключен: включи его и проверь снова."
	}
	return res
}

func realLinkProbe(a *App, st Settings) linkProbe {
	return linkProbe{
		DNS: func(host string) ([]string, error) {
			r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "udp", net.JoinHostPort(st.DNSLocal, "53"))
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			return r.LookupHost(ctx, host)
		},
		TCP: func(addr string) error {
			c, err := net.DialTimeout("tcp", addr, 6*time.Second)
			if err != nil {
				return err
			}
			return c.Close()
		},
		TLS: func(addr, sni string) error {
			d := &net.Dialer{Timeout: 6 * time.Second}
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()
			raw, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return err
			}
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(7 * time.Second))
			c := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
			return c.HandshakeContext(ctx)
		},
		Tunnel: func() (int, error) { return clashDelay(st, "proxy", "https://www.gstatic.com/generate_204") },
	}
}

func (a *App) handleLinkDiag(w http.ResponseWriter, r *http.Request) {
	st := a.settings()
	sv := st.Server
	if sv.Host == "" {
		fail(w, 400, "сервер не выбран")
		return
	}
	running, _, _, _, _ := a.core.Info()
	ready := false
	if running {
		var cn struct{}
		ready = clashGet(st, "/connections", &cn) == nil
	}
	writeJSON(w, 200, runLinkDiag(sv, ready, realLinkProbe(a, st)))
}
