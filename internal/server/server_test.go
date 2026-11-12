package server

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jvch0512/honeynet-live/internal/events"
)

func setup(t *testing.T) (*httptest.Server, *events.Store) {
	t.Helper()
	st := events.NewStore()
	for i := 0; i < 5; i++ {
		st.Add(events.Event{Source: "203.0.113.1", Kind: events.Scan, Severity: 2, Summary: "x"})
	}
	ts := httptest.NewServer((&Server{Store: st}).Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

func TestAPIAndHeaders(t *testing.T) {
	ts, _ := setup(t)
	r, _ := http.Get(ts.URL + "/api/stats")
	var s events.Stats
	if json.NewDecoder(r.Body).Decode(&s) != nil || s.Total != 5 || len(s.PerMinute) != 15 {
		t.Fatalf("%+v", s)
	}
	r, _ = http.Get(ts.URL + "/api/events?limit=2")
	var es []events.Event
	json.NewDecoder(r.Body).Decode(&es)
	if len(es) != 2 || es[0].ID != 5 {
		t.Fatalf("%+v", es)
	}
	r, _ = http.Get(ts.URL + "/api/events?limit=abc")
	es = nil
	json.NewDecoder(r.Body).Decode(&es)
	if len(es) != 5 {
		t.Fatalf("bad limit falls back to the default: %d", len(es))
	}
	for _, p := range []string{"/", "/app.js", "/style.css"} {
		r, err := http.Get(ts.URL + p)
		if err != nil || r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Security-Policy"), "default-src 'self'") {
			t.Fatalf("%s", p)
		}
	}
}

func TestSSE(t *testing.T) {
	ts, st := setup(t)
	r, err := http.Get(ts.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	got := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "data: ") {
				got <- sc.Text()
				return
			}
		}
	}()
	time.Sleep(100 * time.Millisecond)
	st.Add(events.Event{Summary: "live one"})
	select {
	case line := <-got:
		if !strings.Contains(line, "live one") {
			t.Fatal(line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event")
	}
}
