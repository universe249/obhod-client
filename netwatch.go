package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ifaceInfo is what we need to know about a network adapter.
type ifaceInfo struct {
	Name     string
	Up       bool
	Loopback bool
	Addrs    []string // IPv4 addresses
}

// netSnapshot describes the usable networks: the exact addresses (to notice any change)
// and the /24 networks (to recognise "the same place" again).
func netSnapshot(ifs []ifaceInfo) (sig, key string) {
	// virtual adapters (WSL, Hyper-V, VirtualBox, VMware) appear and change when a VM starts: that is not a new network.
	// They are ignored only while a real adapter has an address, because with a Hyper-V external switch the real
	// connection itself is a "vEthernet" adapter.
	realUp := false
	for _, f := range ifs {
		if f.Up && !f.Loopback && !virtualIface(f.Name) && len(usableV4(f.Addrs)) > 0 {
			realUp = true
		}
	}
	var exact, nets []string
	for _, f := range ifs {
		if !f.Up || f.Loopback || realUp && virtualIface(f.Name) {
			continue
		}
		for _, s := range f.Addrs {
			ip := net.ParseIP(s).To4()
			if ip == nil || ip[0] == 169 && ip[1] == 254 || ip[0] == 172 && ip[1] == 19 && ip[2] == 0 { // link-local и наш собственный TUN
				continue
			}
			exact = append(exact, f.Name+"|"+ip.String())
			nets = append(nets, fmt.Sprintf("%d.%d.%d", ip[0], ip[1], ip[2]))
		}
	}
	if len(exact) == 0 {
		return "", ""
	}
	sort.Strings(exact)
	sort.Strings(nets)
	h := sha1.Sum([]byte(strings.Join(dedupe(nets), ",")))
	return strings.Join(exact, ";"), hex.EncodeToString(h[:])[:8]
}

func readIfaces() []ifaceInfo {
	list, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []ifaceInfo
	for _, i := range list {
		fi := ifaceInfo{Name: i.Name, Up: i.Flags&net.FlagUp != 0, Loopback: i.Flags&net.FlagLoopback != 0}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					fi.Addrs = append(fi.Addrs, ipn.IP.String())
				}
			}
		}
		out = append(out, fi)
	}
	return out
}

// netState is shared between the watcher and the watchdog.
type netState struct {
	mu  sync.Mutex
	key string
}

func (n *netState) set(k string) { n.mu.Lock(); n.key = k; n.mu.Unlock() }
func (n *netState) get() string  { n.mu.Lock(); defer n.mu.Unlock(); return n.key }

// netTracker turns readings of the network signature into "the network changed" events:
// a change counts after it has stayed the same for 4 seconds, and at most once per 20 seconds.
// The very first reading is only remembered; coming back from "no network" counts as a change.
type netTracker struct {
	stable, cand string
	since        time.Time
	started      bool
	handled      time.Time
}

func (t *netTracker) step(sig string, now time.Time) bool {
	if sig != t.cand {
		t.cand, t.since = sig, now
	}
	if t.cand == t.stable || now.Sub(t.since) < 4*time.Second {
		return false
	}
	t.stable = t.cand
	first := !t.started
	t.started = true
	if first || t.cand == "" || now.Sub(t.handled) < 20*time.Second {
		return false
	}
	t.handled = now
	return true
}

// sleptBetween: между двумя проверками (раз в 3 секунды) по настенным часам прошло больше 45 секунд — значит,
// компьютер спал. Монотонные часы Go во сне могут стоять, поэтому сравниваем без них (Round(0)).
func sleptBetween(prev, now time.Time) bool {
	return !prev.IsZero() && now.Round(0).Sub(prev.Round(0)) > 45*time.Second
}

func (a *App) netWatchLoop() {
	var tr netTracker
	var last time.Time
	for {
		sig, key := netSnapshot(readIfaces())
		a.net.set(key)
		now := time.Now()
		if sleptBetween(last, now) {
			a.guardGo("resume", a.onResume)
		}
		last = now
		if tr.step(sig, now) {
			a.onNetworkChanged(key)
		}
		select {
		case <-a.quit:
			return
		case <-time.After(3 * time.Second):
		}
	}
}

// onResume: после сна старые соединения туннеля мертвы, а адрес сети часто тот же, поэтому «смены сети» не видно.
// Ждём, пока появится сеть, и переподключаем туннель сразу, не дожидаясь, пока сторож заметит отказ (это минуты).
func (a *App) onResume() {
	if !a.wanted() || !a.core.Running() {
		return
	}
	for i := 0; i < 10; i++ { // до 30 секунд ждём адрес от роутера
		if sig, _ := netSnapshot(readIfaces()); sig != "" {
			break
		}
		select {
		case <-a.quit:
			return
		case <-time.After(3 * time.Second):
		}
	}
	a.event("info", "Компьютер вышел из сна, переподключаю туннель")
	if err := a.restartCore(); err != nil {
		a.event("bad", "Не удалось переподключиться после сна: "+err.Error())
	}
}

// onNetworkChanged reconnects the tunnel on a new network and, if the network is known, starts with the server
// that worked best here.
func (a *App) onNetworkChanged(key string) {
	st := a.settings()
	if !st.NetWatch || !a.wanted() || !a.core.Running() {
		return
	}
	a.event("info", "Сеть изменилась, переподключаю туннель")
	if st.SmartOrder {
		if name, ok := a.smartSwitch(key); ok {
			a.event("info", "Для этой сети лучше работает «"+name+"», переключаюсь")
		}
	}
	if err := a.restartCore(); err != nil {
		a.event("bad", "Не удалось переподключиться после смены сети: "+err.Error())
		return
	}
	// если связи нет и через полминуты, запускаем автоподбор способа
	a.guardGo("netCheck", func() {
		select {
		case <-a.quit:
			return
		case <-time.After(30 * time.Second):
		}
		if !a.core.Running() {
			return
		}
		if _, ok := a.pingProxy(a.settings()); ok {
			return
		}
		if msg, ok := a.autoTune("После смены сети нет связи"); ok {
			a.autoRestart(msg)
		}
	})
}

func virtualIface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range []string{"vethernet", "virtualbox", "vmware", "hyper-v", "wsl", "docker", "vboxnet", "vmnet"} {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

func usableV4(addrs []string) []string {
	var out []string
	for _, s := range addrs {
		ip := net.ParseIP(s).To4()
		if ip == nil || ip[0] == 169 && ip[1] == 254 || ip[0] == 172 && ip[1] == 19 && ip[2] == 0 {
			continue
		}
		out = append(out, s)
	}
	return out
}
