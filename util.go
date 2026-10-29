package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
)

func itoa(n int) string { return strconv.Itoa(n) }

func sprintfURL(tag string) string { return fmt.Sprintf(geositeURL, tag) }

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

func logf(format string, args ...any) { log.Printf(format, args...) }

// rotateLog moves a log that grew past max bytes to path+".1" (replacing the previous one) so it cannot grow forever.
func rotateLog(path string, max int64) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > max {
		_ = os.Remove(path + ".1")
		_ = os.Rename(path, path+".1")
	}
}
