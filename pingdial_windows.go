//go:build windows

package main

import (
	"math/bits"
	"net"
	"syscall"
	"time"
)

const ipUnicastIf, ipv6UnicastIf = 31, 31

// physicalDialers: по одному на каждый настоящий сетевой адаптер. Сокет привязан к адаптеру (IP_UNICAST_IF), поэтому
// соединение идёт мимо нашего TUN — так же sing-box сам выходит в сеть. Без этого при включённом VPN соединение
// «устанавливалось» внутри TUN за 1–3 мс, и пинг серверов был ненастоящим.
func physicalDialers(timeout time.Duration) []*net.Dialer {
	var out []*net.Dialer
	for _, idx := range physicalIfaces() {
		idx := idx
		out = append(out, &net.Dialer{Timeout: timeout, Control: func(network, _ string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				if network == "tcp6" || network == "udp6" {
					serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, ipv6UnicastIf, idx)
				} else { // для IPv4 номер адаптера передаётся в сетевом порядке байт
					serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipUnicastIf, int(bits.ReverseBytes32(uint32(idx))))
				}
			})
			if err != nil {
				return err
			}
			return serr
		}})
	}
	return out
}
