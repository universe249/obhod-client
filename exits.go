package main

// Every saved server gets a forced exit in the local test proxy (see probe.go). On top of that each
// server gets "ways": the same server with TLS fragmentation or multiplexing flipped. They cost nothing
// when idle and let the auto-tuner compare ways to connect without restarting the core.

const (
	kindBase = ""   // the server as saved
	kindFrag = "f"  // fragmentation flipped
	kindMux  = "m"  // multiplex flipped
	kindFP1  = "u1" // another TLS fingerprint (first alternative)
	kindFP2  = "u2" // another TLS fingerprint (second alternative)
)

// fpPool is what the tuner tries when the saved fingerprint does not get through on this network.
var fpPool = []string{"chrome", "firefox", "safari", "ios"}

// effectiveFP is the fingerprint the config really uses for the server ("" when there is no uTLS).
func effectiveFP(s Server) string {
	if needsXray(s) || (s.Type != "vless" && s.Type != "trojan") {
		return ""
	}
	if s.Type == "vless" && s.Security != "tls" && s.Security != "reality" {
		return ""
	}
	if s.Type == "trojan" && s.Security == "none" {
		return ""
	}
	if s.Fingerprint == "" && s.Security == "reality" {
		return "chrome"
	}
	return s.Fingerprint
}

// altFingerprints lists up to two fingerprints other than the current one; nil when the server does not use uTLS.
func altFingerprints(s Server) []string {
	cur := effectiveFP(s)
	if cur == "" && !(s.Type == "vless" && (s.Security == "tls" || s.Security == "reality")) {
		return nil
	}
	if needsXray(s) || (s.Type != "vless" && s.Type != "trojan") {
		return nil
	}
	var out []string
	for _, f := range fpPool {
		if f != cur && len(out) < 2 {
			out = append(out, f)
		}
	}
	return out
}

func fpKinds() []string { return []string{kindFP1, kindFP2} }

type exitSpec struct {
	Server int    // index in allServers(st); 0 is the active one
	Kind   string // kindBase | kindFrag | kindMux
	Tag    string // sing-box outbound tag
	User   string // test proxy user that selects this exit
	Out    m
}

func exitTag(i int, kind string) string {
	if kind == kindBase {
		return "srv-" + itoa(i)
	}
	return "srv-" + itoa(i) + "-" + kind
}

func exitUser(i int, kind string) string { return "s" + itoa(i) + kind }

// probeUserFor is the base exit of saved server i.
func probeUserFor(i int) string { return exitUser(i, kindBase) }

// serverExits builds the outbounds of all exits. Base exits only exist with two or more servers
// (with one server the "proxy" outbound already is it).
func serverExits(st Settings, servers []Server) []exitSpec {
	var out []exitSpec
	mk := func(i int, sv Server, kind string, frag bool) (exitSpec, bool) {
		o, err := outboundFor(sv, st.XrayPort)
		if err != nil {
			return exitSpec{}, false
		}
		o["tag"] = exitTag(i, kind)
		if frag {
			applyFragment(o)
		}
		pinOutbound(o)
		return exitSpec{Server: i, Kind: kind, Tag: exitTag(i, kind), User: exitUser(i, kind), Out: o}, true
	}
	for i, sv := range servers {
		if needsXray(sv) {
			continue
		}
		frag := fragFor(st, sv)
		if len(servers) >= 2 {
			if e, ok := mk(i, sv, kindBase, frag); ok {
				out = append(out, e)
			}
		}
		if base, err := outboundFor(sv, st.XrayPort); err == nil && fragEligible(base) {
			if e, ok := mk(i, sv, kindFrag, !frag); ok {
				out = append(out, e)
			}
		}
		for k, fp := range altFingerprints(sv) {
			v := sv
			v.Fingerprint = fp
			if e, ok := mk(i, v, fpKinds()[k], frag); ok {
				out = append(out, e)
			}
		}
		if muxable(sv) {
			v := sv
			v.Mux = !sv.Mux
			if e, ok := mk(i, v, kindMux, frag); ok {
				out = append(out, e)
			}
		}
	}
	return out
}
