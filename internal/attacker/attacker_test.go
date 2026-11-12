package attacker

import (
	"context"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jvch0512/honeynet-live/internal/events"
	"github.com/jvch0512/honeynet-live/internal/honeypot"
)

func TestSimulatorEndToEnd(t *testing.T) {
	st := events.NewStore()
	hs := httptest.NewServer(&honeypot.HTTPHandler{Store: st, TrustXFF: true})
	defer hs.Close()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { (&honeypot.Telnet{Store: st, ProxyProtocol: true}).Serve(ctx, ln); close(done) }()
	defer func() { cancel(); <-done }()

	sim := New(strings.TrimPrefix(hs.URL, "http://"), ln.Addr().String(), 5)
	seen := map[string]int{}
	for i := 0; i < 40; i++ {
		seen[sim.Step(ctx)]++
	}
	for _, a := range Actors {
		if seen[a] == 0 {
			t.Fatalf("actor %s never ran in 40 steps: %v", a, seen)
		}
	}
	deadline := time.Now().Add(6 * time.Second)
	var kinds map[events.Kind]bool
	for time.Now().Before(deadline) {
		kinds = map[events.Kind]bool{}
		for _, e := range st.Recent(0) {
			kinds[e.Kind] = true
		}
		if kinds[events.Malware] && kinds[events.Exploit] && kinds[events.Scan] && kinds[events.BruteForce] {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, k := range []events.Kind{events.Malware, events.Exploit, events.Scan, events.BruteForce} {
		if !kinds[k] {
			t.Errorf("no %s events captured: %v", k, kinds)
		}
	}
	for _, e := range st.Recent(0) {
		ok := false
		for _, r := range ranges {
			ok = ok || strings.HasPrefix(e.Source, r)
		}
		if !ok {
			t.Fatalf("every simulated source must be a documentation address, got %s", e.Source)
		}
	}
	if len(st.Stats().IOCs) == 0 || !strings.HasPrefix(st.Stats().IOCs[0].Name, "hxxp://") {
		t.Fatalf("defanged malware URLs expected: %+v", st.Stats().IOCs)
	}
}

func TestSameSeedSameActors(t *testing.T) {
	seq := func() string {
		s := New("127.0.0.1:1", "127.0.0.1:1", 9) // nothing listens: steps fail fast but the actor choice stays deterministic
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var out []string
		for i := 0; i < 8; i++ {
			out = append(out, s.Step(ctx))
		}
		return strings.Join(out, ",")
	}
	if a, b := seq(), seq(); a != b {
		t.Fatalf("%s != %s", a, b)
	}
}
