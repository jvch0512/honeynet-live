package events

import (
	"fmt"
	"testing"
	"time"
)

func TestAddStatsAndOrdering(t *testing.T) {
	s := NewStore()
	for i := 0; i < 3; i++ {
		s.Add(Event{Source: "1.1.1.1", Kind: BruteForce})
	}
	s.Add(Event{Source: "2.2.2.2", Kind: Scan, IOC: "hxxp://x[.]y/a"})
	s.RecordCred("root", "toor")
	s.RecordCred("root", "toor")
	s.RecordCred("admin", "admin")
	s.RecordPath("/.env")
	st := s.Stats()
	if st.Total != 4 || st.Sources != 2 || st.ByKind[0].Name != string(BruteForce) || st.ByKind[0].Count != 3 {
		t.Fatalf("%+v", st.ByKind)
	}
	if st.TopSources[0] != (Count{"1.1.1.1", 3}) || st.TopCreds[0] != (Count{"root / toor", 2}) || st.IOCs[0].Name != "hxxp://x[.]y/a" || st.TopPaths[0].Name != "/.env" {
		t.Fatalf("%+v", st)
	}
	if len(st.PerMinute) != 15 || st.PerMinute[14] != 4 {
		t.Fatalf("current minute should hold 4 events: %v", st.PerMinute)
	}
}

func TestRingBufferAndRecent(t *testing.T) {
	s := NewStore()
	for i := 1; i <= maxEvents+25; i++ {
		s.Add(Event{Kind: Probe})
	}
	r := s.Recent(2)
	if len(r) != 2 || r[0].ID != maxEvents+25 || r[1].ID != maxEvents+24 {
		t.Fatalf("newest first: %+v", r)
	}
	if len(s.Recent(0)) != maxEvents || s.Stats().Total != maxEvents+25 {
		t.Fatal("buffer capped, total keeps counting")
	}
}

func TestCounterKeysAreBounded(t *testing.T) {
	s := NewStore()
	for i := 0; i < maxKeys+500; i++ {
		s.RecordCred(fmt.Sprintf("u%d", i), "x")
		s.RecordPath(fmt.Sprintf("/p%d", i))
		s.Add(Event{Source: fmt.Sprintf("10.0.%d.%d", i/250, i%250), Kind: Probe})
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.creds) > maxKeys || len(s.paths) > maxKeys || len(s.src) > maxKeys {
		t.Fatalf("an attacker must not be able to grow memory without bound: %d %d %d", len(s.creds), len(s.paths), len(s.src))
	}
}

func TestPerMinuteUsesInjectedClockAndForgetsOldMinutes(t *testing.T) {
	s := NewStore()
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }
	s.Add(Event{Time: base.Add(-10 * time.Minute)})
	s.Add(Event{Time: base})
	if st := s.Stats(); st.PerMinute[4] != 1 || st.PerMinute[14] != 1 {
		t.Fatalf("%v", st.PerMinute)
	}
	s.Add(Event{Time: base.Add(time.Hour)}) // a much newer event evicts the old buckets
	s.mu.RLock()
	n := len(s.minute)
	s.mu.RUnlock()
	if n != 1 {
		t.Fatalf("old minute buckets must be dropped, have %d", n)
	}
}

func TestSubscribeAndSlowConsumer(t *testing.T) {
	s := NewStore()
	ch, cancel := s.Subscribe()
	s.Add(Event{Summary: "a"})
	if e := <-ch; e.Summary != "a" || e.ID != 1 || e.Time.IsZero() {
		t.Fatalf("%+v", e)
	}
	for i := 0; i < 300; i++ {
		s.Add(Event{})
	}
	cancel()
	cancel()
	s.Add(Event{})
	if s.Stats().Total != 302 {
		t.Fatal("a stalled subscriber must never block capture")
	}
}
