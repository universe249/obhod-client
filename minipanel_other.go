//go:build !windows

package main

func toggleMiniPanel(url, dataDir string, openMain func()) bool { return false }
