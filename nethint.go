package main

import (
	"net"
	"sync"
	"time"
)

// Когда связь с сервером пропала, проверяем, в чём дело: в интернете вообще, в DNS или в пути до сервера.

type netVerdict struct {
	Title, Fix string
}

func verdictFor(internetOK, dnsOK, serverOK bool) (netVerdict, bool) {
	switch {
	case serverOK:
		return netVerdict{}, false
	case !internetOK:
		return netVerdict{"Нет интернета без туннеля",
			"Проверь кабель и роутер. Если роутер «завис», перезагрузи его. Туннель восстановится сам, когда интернет вернётся."}, true
	case !dnsOK:
		return netVerdict{"Не работает DNS (определение адресов)",
			"Интернет есть, но имена не определяются: чаще всего виноват DNS роутера. Перезагрузи роутер или задай DNS 1.1.1.1 и 8.8.8.8 в настройках роутера или Windows. Если программа уже запоминала адрес сервера, она подключится по нему."}, true
	default:
		return netVerdict{"Интернет есть, а сервер недоступен",
			"Похоже, провайдер или роутер не пропускает соединение именно с твоим сервером (или сервер выключен). Помогает перезагрузка роутера, смена порта или сервера из «Мои серверы». Если на телефоне через мобильную сеть всё работает, дело в домашней сети."}, true
	}
}

type netHintState struct {
	mu   sync.Mutex
	text netVerdict
	has  bool
	at   time.Time
}

var netHint netHintState

func (h *netHintState) set(v netVerdict, ok bool) {
	h.mu.Lock()
	h.text, h.has, h.at = v, ok, time.Now()
	h.mu.Unlock()
}

func (h *netHintState) get() (netVerdict, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.has || time.Since(h.at) > 30*time.Minute {
		return netVerdict{}, false
	}
	return h.text, true
}

func tcpOK(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// probeNetwork вызывается, когда связь с сервером пропала. Идёт мимо туннеля (до него «Туннель» включён, но прямые адреса
// 1.1.1.1 и 8.8.8.8 проверяют именно сеть, а не сервер).
func probeNetwork(st Settings) {
	s := applyHostOverride(st.Server)
	internet := tcpOK("1.1.1.1:443") || tcpOK("8.8.8.8:443")
	dns := true
	if net.ParseIP(st.Server.Host) == nil && st.Server.Host != "" {
		_, err := lookupHostFn(st.Server.Host)
		dns = err == nil
	}
	server := tcpOK(net.JoinHostPort(s.Host, itoa(s.Port)))
	netHint.set(verdictFor(internet, dns, server))
}
