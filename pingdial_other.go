//go:build !windows

package main

import (
	"net"
	"time"
)

// physicalDialers: вне Windows TUN приложения не используется, обходить нечего.
func physicalDialers(timeout time.Duration) []*net.Dialer { return nil }
