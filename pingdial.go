package main

import (
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// physicalIfaces: номера настоящих адаптеров с адресом (без нашего TUN, петли и, по возможности, виртуальных).
func physicalIfaces() []int {
	list, err := net.Interfaces()
	if err != nil {
		return nil
	}
	type cand struct {
		idx     int
		virtual bool
	}
	var cs []cand
	for _, i := range list {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		var v4 []string
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					v4 = append(v4, ipn.IP.String())
				}
			}
		}
		if len(usableV4(v4)) == 0 { // usableV4 отбрасывает и адрес нашего TUN (172.19.0.x)
			continue
		}
		low := strings.ToLower(i.Name)
		if strings.Contains(low, "tun") || strings.Contains(low, "sing") {
			continue
		}
		cs = append(cs, cand{i.Index, virtualIface(i.Name)})
	}
	sort.SliceStable(cs, func(a, b int) bool { return !cs[a].virtual && cs[b].virtual })
	out := make([]int, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.idx)
	}
	return out
}

type pingOpts struct {
	VPN     bool                          // туннель включён: обычное соединение «ответит» изнутри TUN
	Dialers []*net.Dialer                 // соединения мимо TUN (Windows); пусто — обычное
	Delay   func(tag string) (int, error) // замер через ядро (для Hysteria2, у которой TCP нет)
	Tags    map[int]string                // номер сервера в списке -> выход ядра с этим сервером
}

// fakeConnectMs: быстрее этого «настоящий» сервер в интернете не отвечает — значит, соединение замкнулось в TUN.
const fakeConnectMs = 4

// pingProfiles меряет время установки TCP-соединения с каждым сервером. Hysteria2 работает по UDP: её проверяем
// через ядро (запрос через этот сервер), если VPN включён и сервер есть в его настройках.
func pingProfiles(list []Server, o pingOpts) []pingResult {
	res := make([]pingResult, len(list))
	var wg sync.WaitGroup
	for i, s := range list {
		res[i] = pingResult{Index: i, Ms: -1}
		if s.Type == "hysteria2" {
			res[i].Note = "udp"
			if tag := o.Tags[i]; o.VPN && o.Delay != nil && tag != "" {
				wg.Add(1)
				go func(i int, tag string) {
					defer wg.Done()
					if ms, err := o.Delay(tag); err == nil && ms > 0 {
						res[i] = pingResult{Index: i, Ms: ms, Note: "core"}
					} else {
						res[i] = pingResult{Index: i, Ms: -1, Note: "core"}
					}
				}(i, tag)
			}
			continue
		}
		wg.Add(1)
		go func(i int, s Server) {
			defer wg.Done()
			addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
			dial := func(d *net.Dialer) int {
				best := -1
				for k := 0; k < 2; k++ {
					t0 := time.Now()
					c, err := d.Dial("tcp", addr)
					if err != nil {
						continue
					}
					c.Close()
					if ms := int(time.Since(t0).Milliseconds()); best < 0 || ms < best {
						best = ms
					}
				}
				return best
			}
			if o.VPN {
				for _, d := range o.Dialers {
					if ms := dial(d); ms >= 0 {
						res[i].Ms = ms
						return
					}
				}
			}
			ms := dial(&net.Dialer{Timeout: 2 * time.Second})
			if o.VPN && ms >= 0 && ms < fakeConnectMs && !isPrivateHost(s.Host) {
				res[i].Note = "vpn" // ответил сам TUN: настоящую задержку так не узнать
				return
			}
			res[i].Ms = ms
		}(i, s)
	}
	wg.Wait()
	return res
}

func isPrivateHost(h string) bool {
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// coreTags находит в запущенной конфигурации ядра выход для каждого сервера Hysteria2 из списка
// (по типу, адресу и порту, а не по номеру: список мог поменяться после запуска).
func coreTags(cfg []byte, list []Server) map[int]string {
	var c struct {
		Outbounds []struct {
			Type   string `json:"type"`
			Tag    string `json:"tag"`
			Server string `json:"server"`
			Port   int    `json:"server_port"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(cfg, &c) != nil {
		return nil
	}
	out := map[int]string{}
	for i, s := range list {
		if s.Type != "hysteria2" {
			continue
		}
		for _, ob := range c.Outbounds {
			base := ob.Tag == "proxy" || ob.Tag == "proxy-main" || strings.HasPrefix(ob.Tag, "path-") ||
				strings.HasPrefix(ob.Tag, "srv-") && strings.Count(ob.Tag, "-") == 1
			// адрес в конфигурации мог быть заменён на закреплённый IP (pin.go)
			sameHost := ob.Server == s.Host || ob.Server != "" && ob.Server == pinnedIP(s.Host)
			if base && ob.Type == "hysteria2" && sameHost && ob.Port == s.Port {
				out[i] = ob.Tag
				break
			}
		}
	}
	return out
}
