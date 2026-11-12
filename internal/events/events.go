// Package events stores honeypot events, keeps aggregate statistics and fans events out to live subscribers.
package events

import (
	"sort"
	"sync"
	"time"
)

type Kind string

const (
	Scan       Kind = "recon-scan"
	Exploit    Kind = "exploit-attempt"
	BruteForce Kind = "credential-attack"
	Malware    Kind = "malware-download"
	Command    Kind = "shell-command"
	Probe      Kind = "probe"
)

type Event struct {
	ID       int       `json:"id"`
	Time     time.Time `json:"time"`
	Service  string    `json:"service"` // http or telnet
	Source   string    `json:"source"`
	Kind     Kind      `json:"kind"`
	Severity int       `json:"severity"` // 1 to 4
	Summary  string    `json:"summary"`
	Detail   string    `json:"detail,omitempty"`
	IOC      string    `json:"ioc,omitempty"` // extracted indicator, e.g. a malware URL
}

type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type Stats struct {
	Total      int     `json:"total"`
	Sources    int     `json:"sources"` // distinct source addresses seen
	ByKind     []Count `json:"by_kind"`
	TopSources []Count `json:"top_sources"`
	TopCreds   []Count `json:"top_credentials"`
	TopPaths   []Count `json:"top_paths"`
	IOCs       []Count `json:"iocs"`
	PerMinute  []int   `json:"per_minute"` // last 15 minutes, oldest first
}

const (
	maxEvents = 500
	maxKeys   = 2000 // cap on distinct counter keys so an attacker cannot grow memory without bound
)

type Store struct {
	mu     sync.RWMutex
	events []Event
	id     int
	kind   map[Kind]int
	src    map[string]int
	creds  map[string]int
	paths  map[string]int
	iocs   map[string]int
	minute map[int64]int
	subs   map[chan Event]struct{}
	now    func() time.Time
}

func NewStore() *Store {
	return &Store{kind: map[Kind]int{}, src: map[string]int{}, creds: map[string]int{}, paths: map[string]int{}, iocs: map[string]int{}, minute: map[int64]int{}, subs: map[chan Event]struct{}{}, now: time.Now}
}

func bump(m map[string]int, k string) {
	if k == "" {
		return
	}
	if _, ok := m[k]; !ok && len(m) >= maxKeys {
		return
	}
	m[k]++
}

// Add stamps and stores an event, updating counters. Credentials and paths are recorded separately with RecordCred / RecordPath.
func (s *Store) Add(e Event) Event {
	s.mu.Lock()
	s.id++
	e.ID = s.id
	if e.Time.IsZero() {
		e.Time = s.now().UTC()
	}
	s.events = append(s.events, e)
	if len(s.events) > maxEvents {
		s.events = append([]Event(nil), s.events[len(s.events)-maxEvents:]...)
	}
	s.kind[e.Kind]++
	bump(s.src, e.Source)
	bump(s.iocs, e.IOC)
	s.minute[e.Time.Unix()/60]++
	for k := range s.minute {
		if k < e.Time.Unix()/60-30 {
			delete(s.minute, k)
		}
	}
	for ch := range s.subs {
		select {
		case ch <- e:
		default:
		}
	}
	s.mu.Unlock()
	return e
}

func (s *Store) RecordCred(user, pass string) {
	s.mu.Lock()
	bump(s.creds, user+" / "+pass)
	s.mu.Unlock()
}

func (s *Store) RecordPath(p string) {
	s.mu.Lock()
	bump(s.paths, p)
	s.mu.Unlock()
}

func (s *Store) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		if _, ok := s.subs[ch]; ok {
			delete(s.subs, ch)
			close(ch)
		}
		s.mu.Unlock()
	}
}

func (s *Store) Recent(n int) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n <= 0 || n > len(s.events) {
		n = len(s.events)
	}
	out := make([]Event, 0, n)
	for i := len(s.events) - 1; i >= len(s.events)-n; i-- {
		out = append(out, s.events[i])
	}
	return out
}

func top(m map[string]int, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Stats{Total: s.id, Sources: len(s.src), TopSources: top(s.src, 6), TopCreds: top(s.creds, 8), TopPaths: top(s.paths, 8), IOCs: top(s.iocs, 6)}
	for k, v := range s.kind {
		st.ByKind = append(st.ByKind, Count{string(k), v})
	}
	sort.Slice(st.ByKind, func(i, j int) bool {
		if st.ByKind[i].Count != st.ByKind[j].Count {
			return st.ByKind[i].Count > st.ByKind[j].Count
		}
		return st.ByKind[i].Name < st.ByKind[j].Name
	})
	cur := s.now().UTC().Unix() / 60
	for m := cur - 14; m <= cur; m++ {
		st.PerMinute = append(st.PerMinute, s.minute[m])
	}
	return st
}
