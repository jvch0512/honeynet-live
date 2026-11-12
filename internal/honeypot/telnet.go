package honeypot

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jvch0512/honeynet-live/internal/events"
)

const (
	maxLine      = 256
	maxCommands  = 20
	sessionLimit = 90 * time.Second
	idleLimit    = 20 * time.Second
	maxSessions  = 64
)

// Telnet is a low-interaction Telnet honeypot. It accepts any credentials on the third attempt, then offers a fake
// shell that only logs: no command is ever executed, and nothing is read from or written to the filesystem.
type Telnet struct {
	Store *events.Store
	// ProxyProtocol makes the server read an optional HAProxy "PROXY TCP4 <src> <dst> <sp> <dp>" first line,
	// which the demo attack simulator uses to label connections with documentation-range addresses.
	ProxyProtocol bool
	sem           chan struct{}
}

// ParseProxyLine returns the source address from a PROXY protocol v1 header.
func ParseProxyLine(line string) (string, bool) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) != 6 || f[0] != "PROXY" || (f[1] != "TCP4" && f[1] != "TCP6") {
		return "", false
	}
	if ip := net.ParseIP(f[2]); ip == nil {
		return "", false
	}
	return f[2], true
}

// Serve accepts connections until ctx is cancelled.
func (t *Telnet) Serve(ctx context.Context, ln net.Listener) {
	t.sem = make(chan struct{}, maxSessions)
	go func() { <-ctx.Done(); ln.Close() }()
	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			wg.Wait()
			return
		}
		select {
		case t.sem <- struct{}{}:
		default:
			c.Close() // too many sessions: shed load instead of growing without bound
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-t.sem }()
			t.handle(c)
		}()
	}
}

func readLine(r *bufio.Reader, c net.Conn) (string, error) {
	c.SetReadDeadline(time.Now().Add(idleLimit))
	var b []byte
	for len(b) < maxLine {
		x, err := r.ReadByte()
		if err != nil {
			return string(b), err
		}
		if x == '\n' {
			return strings.TrimRight(string(b), "\r"), nil
		}
		if x >= 32 && x < 127 { // drop telnet negotiation bytes and control characters
			b = append(b, x)
		}
	}
	return string(b), nil // an over-long line is truncated, not buffered
}

func (t *Telnet) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(sessionLimit))
	r := bufio.NewReaderSize(c, 512)
	src := ""
	if host, _, err := net.SplitHostPort(c.RemoteAddr().String()); err == nil {
		src = host
	}
	if t.ProxyProtocol {
		if p, err := r.Peek(5); err == nil && string(p) == "PROXY" {
			line, _ := readLine(r, c)
			if s, ok := ParseProxyLine(line); ok {
				src = s
			}
		}
	}
	t.Store.Add(events.Event{Service: "telnet", Source: src, Kind: events.Probe, Severity: 1, Summary: "Telnet connection opened"})
	fmt.Fprint(c, "\r\nBusyBox v1.22.1 built-in shell (ash)\r\n")
	var user, pass string
	for try := 1; try <= 3; try++ {
		fmt.Fprint(c, "login: ")
		u, err := readLine(r, c)
		if err != nil {
			return
		}
		fmt.Fprint(c, "Password: ")
		p, err := readLine(r, c)
		if err != nil {
			return
		}
		user, pass = clip(u, 40), clip(p, 40)
		t.Store.RecordCred(user, pass)
		t.Store.Add(events.Event{Service: "telnet", Source: src, Kind: events.BruteForce, Severity: 3, Summary: "Credential attempt", Detail: fmt.Sprintf("%s / %s", user, pass)})
		if try < 3 {
			fmt.Fprint(c, "\r\nLogin incorrect\r\n")
		}
	}
	fmt.Fprint(c, "\r\n# ")
	for n := 0; n < maxCommands; n++ {
		line, err := readLine(r, c)
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			fmt.Fprint(c, "# ")
			continue
		}
		v := ParseShell(line)
		ev := events.Event{Service: "telnet", Source: src, Kind: v.Kind, Severity: v.Severity, Summary: v.Summary, Detail: clip(line, 200)}
		if v.Kind == events.Malware {
			ev.IOC = ExtractURL(line)
		}
		t.Store.Add(ev)
		if line == "exit" || line == "logout" {
			return
		}
		fmt.Fprintf(c, "%s\r\n# ", fakeOutput(line))
	}
}

// fakeOutput returns canned text so the fake shell feels alive. It never reflects attacker-controlled data back.
func fakeOutput(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.HasPrefix(l, "uname"):
		return "Linux router 3.10.14 #1 SMP armv7l GNU/Linux"
	case strings.HasPrefix(l, "whoami"), strings.HasPrefix(l, "id"):
		return "root"
	case strings.Contains(l, "wget"), strings.Contains(l, "curl"):
		return "Connecting... failed: Network is unreachable"
	case strings.Contains(l, "/etc/passwd"):
		return "root:x:0:0:root:/root:/bin/ash"
	}
	return "sh: command not found"
}
