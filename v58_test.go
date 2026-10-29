package main

import "testing"

func TestSyncProfilesAfterReset(t *testing.T) {
	old := Server{Name: "vless-2083", Type: "vless", Host: "h", Port: 2083, Network: "tcp", UUID: "old", Frag: "on"}
	oldHy := Server{Name: "hy", Type: "hysteria2", Host: "h", Port: 443, Password: "oldpw"}
	st := Settings{Server: old, Profiles: []Server{old, oldHy}}

	nw := old
	nw.UUID, nw.Frag = "new", ""
	nwHy := oldHy
	nwHy.Password = "newpw"

	// after a reset the subscription gives the same servers with new credentials
	a, u := syncProfiles(&st, []Server{nw, nwHy})
	if a != 0 || u != 2 || len(st.Profiles) != 2 {
		t.Fatalf("added=%d updated=%d profiles=%d", a, u, len(st.Profiles))
	}
	if st.Profiles[0].UUID != "new" || st.Profiles[0].Frag != "on" || st.Profiles[1].Password != "newpw" {
		t.Fatalf("not updated in place: %+v", st.Profiles)
	}
	if st.Server.UUID != "new" || st.Server.Frag != "on" {
		t.Fatalf("active server not updated: %+v", st.Server)
	}

	// the list that was already duplicated by the old app version collapses
	st2 := Settings{Server: old, Profiles: []Server{old, oldHy, nw, nwHy}}
	syncProfiles(&st2, []Server{nw, nwHy})
	if len(st2.Profiles) != 2 || st2.Server.UUID != "new" {
		t.Fatalf("duplicates stayed: %d, active %q", len(st2.Profiles), st2.Server.UUID)
	}

	// nothing changes on a repeat, a really new server is added
	if a, u := syncProfiles(&st, []Server{nw, nwHy}); a != 0 || u != 0 {
		t.Fatalf("repeat: %d %d", a, u)
	}
	extra := Server{Name: "new", Type: "vless", Host: "h2", Port: 1, Network: "tcp", UUID: "x"}
	if a, _ := syncProfiles(&st, []Server{extra}); a != 1 || len(st.Profiles) != 3 {
		t.Fatalf("new server not added")
	}
}

func TestOpenJudge(t *testing.T) {
	if lv, _ := openJudge(200, "", ""); lv != lvOK {
		t.Fatal("200")
	}
	if lv, _ := openJudge(403, "", ""); lv != lvBad {
		t.Fatal("403")
	}
	if lv, _ := openJudge(429, "", ""); lv != lvUnknown {
		t.Fatal("429")
	}
	if lv, _ := openJudge(503, "", ""); lv != lvUnknown {
		t.Fatal("503")
	}
	ids := map[string]bool{}
	for _, p := range svcProbes {
		if ids[p.ID] || p.URL == "" || p.Judge == nil {
			t.Fatalf("bad probe %q", p.ID)
		}
		ids[p.ID] = true
	}
	for _, id := range []string{"telegram", "discord", "steam", "steamcom", "tiktok", "instagram", "twitch", "github"} {
		if !ids[id] {
			t.Fatalf("missing %s", id)
		}
	}
}

func TestVersion510(t *testing.T) {
	if !newerVersion("5.10", "5.9") || newerVersion("5.9", "5.10") || !newerVersion("5.10", "5.9.1") {
		t.Fatal("5.10 must be newer than 5.9")
	}
}
