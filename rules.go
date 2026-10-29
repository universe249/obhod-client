package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// RuleSet is a sing-box binary rule-set (.srs) that we keep locally.
type RuleSet struct {
	Tag  string
	URLs []string
}

func ruleSetFor(tag string) RuleSet {
	switch tag {
	case "ru-blocked-domains":
		return RuleSet{tag, []string{ruBlockedDomainsURL,
			"https://cdn.jsdelivr.net/gh/runetfreedom/russia-v2ray-rules-dat@release/sing-box/rule-set-geosite/geosite-ru-blocked.srs"}}
	case "ru-blocked-ip":
		return RuleSet{tag, []string{ruBlockedIPURL,
			"https://cdn.jsdelivr.net/gh/runetfreedom/russia-v2ray-rules-dat@release/sing-box/rule-set-geoip/geoip-ru-blocked.srs"}}
	case adsTag:
		// реклама и трекеры: большой список runetfreedom (есть российские сети, например реклама и метрика Яндекса), запасной — SagerNet
		return RuleSet{tag, []string{
			"https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-category-ads-all.srs",
			"https://cdn.jsdelivr.net/gh/runetfreedom/russia-v2ray-rules-dat@release/sing-box/rule-set-geosite/geosite-category-ads-all.srs",
			sprintfURL("category-ads-all")}}
	}
	name := strings.TrimPrefix(tag, "geosite-")
	return RuleSet{tag, []string{sprintfURL(name),
		"https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-" + name + ".srs"}}
}

func rulesDir(dataDir string) string { return filepath.Join(dataDir, "rules") }

func ruleSetPath(dataDir, tag string) string {
	return filepath.Join(rulesDir(dataDir), tag+".srs")
}

// validSRS checks the file looks like a sing-box rule-set ("SRS" magic).
func validSRS(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 4)
	n, _ := io.ReadFull(f, b)
	return n >= 4 && string(b[:3]) == "SRS"
}

var rsClient = &http.Client{Timeout: 15 * time.Second}

func downloadRuleSet(dataDir string, rs RuleSet) error {
	if err := os.MkdirAll(rulesDir(dataDir), 0o755); err != nil {
		return err
	}
	var last error
	for _, u := range rs.URLs {
		resp, err := rsClient.Get(u)
		if err != nil {
			last = err
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20+1))
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if len(data) > 16<<20 {
			last = fmt.Errorf("список слишком большой")
			continue
		}
		if resp.StatusCode != 200 {
			last = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		if len(data) < 8 || string(data[:3]) != "SRS" {
			last = fmt.Errorf("получен не список правил")
			continue
		}
		dst := ruleSetPath(dataDir, rs.Tag)
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, dst)
	}
	if last == nil {
		last = fmt.Errorf("нет адресов")
	}
	return last
}

// ensureRuleSets makes sure every needed list exists locally.
// force re-downloads everything (keeping the old copy when the download fails).
// It returns the tags that are still missing and a map tag -> error text for failed downloads.
func ensureRuleSets(st Settings, dataDir string, force bool) (missing []string, errs map[string]string) {
	tags := neededTags(st)
	errs = map[string]string{}
	deadline := time.Now().Add(45 * time.Second) // no internet must not block the start for minutes
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, tag := range tags {
		path := ruleSetPath(dataDir, tag)
		if !force && validSRS(path) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(tag, path string) {
			defer wg.Done()
			defer func() { <-sem }()
			var err error
			if time.Now().After(deadline) {
				err = fmt.Errorf("время ожидания вышло")
			} else {
				err = downloadRuleSet(dataDir, ruleSetFor(tag))
			}
			if err != nil {
				mu.Lock()
				errs[tag] = err.Error()
				if !validSRS(path) {
					missing = append(missing, tag)
				}
				mu.Unlock()
			}
		}(tag, path)
	}
	wg.Wait()
	sort.Strings(missing)
	return missing, errs
}

// refreshStale quietly updates lists older than maxAge; failures are ignored.
func refreshStale(st Settings, dataDir string, maxAge time.Duration) {
	for _, tag := range neededTags(st) {
		fi, err := os.Stat(ruleSetPath(dataDir, tag))
		if err == nil && time.Since(fi.ModTime()) < maxAge {
			continue
		}
		_ = downloadRuleSet(dataDir, ruleSetFor(tag))
	}
}

type ruleSetInfo struct {
	Tag     string `json:"tag"`
	OK      bool   `json:"ok"`
	Size    int64  `json:"size"`
	Updated string `json:"updated"`
}

func ruleSetStatus(st Settings, dataDir string) []ruleSetInfo {
	var out []ruleSetInfo
	for _, tag := range neededTags(st) {
		p := ruleSetPath(dataDir, tag)
		info := ruleSetInfo{Tag: tag, OK: validSRS(p)}
		if fi, err := os.Stat(p); err == nil {
			info.Size = fi.Size()
			info.Updated = fi.ModTime().Format("02.01 15:04")
		}
		out = append(out, info)
	}
	return out
}

// ruleFilesStamp changes whenever a used list file changes (so the UI can offer a restart).
func ruleFilesStamp(st Settings, dataDir string, skip map[string]bool) string {
	var b strings.Builder
	for _, tag := range neededTags(st) {
		if skip[tag] {
			continue
		}
		if fi, err := os.Stat(ruleSetPath(dataDir, tag)); err == nil {
			fmt.Fprintf(&b, "%s:%d:%d;", tag, fi.Size(), fi.ModTime().Unix())
		}
	}
	return b.String()
}
