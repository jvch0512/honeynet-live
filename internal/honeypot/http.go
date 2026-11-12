package honeypot

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jvch0512/honeynet-live/internal/events"
)

const maxBody = 4096

// HTTPHandler serves canned fake pages and records every request. TrustXFF should only be true in demo mode,
// where the built-in attack simulator labels its traffic with documentation-range addresses.
type HTTPHandler struct {
	Store    *events.Store
	TrustXFF bool
}

func (h *HTTPHandler) source(r *http.Request) string {
	if h.TrustXFF {
		if x := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(x) != nil {
			return x
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

const loginPage = `<!doctype html><html><head><title>Admin Login</title></head><body><h1>Administration</h1><form method="post"><input name="user"><input name="pass" type="password"><button>Sign in</button></form></body></html>`

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))
	ua := r.UserAgent()
	v := ClassifyHTTP(r.Method, r.URL.RequestURI(), ua, string(body))
	src := h.source(r)
	path := r.URL.Path
	h.Store.RecordPath(clip(path, 60))
	detail := fmt.Sprintf("%s %s | UA: %s", r.Method, clip(r.URL.RequestURI(), 160), clip(ua, 80))
	if r.Method == http.MethodPost && len(body) > 0 {
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		if err := r.ParseForm(); err == nil {
			if u, p := r.PostForm.Get("user"), r.PostForm.Get("pass"); u != "" {
				h.Store.RecordCred(clip(u, 30), clip(p, 30))
				detail += fmt.Sprintf(" | creds tried: %s / %s", clip(u, 30), clip(p, 30))
			}
		}
	}
	h.Store.Add(events.Event{Service: "http", Source: src, Kind: v.Kind, Severity: v.Severity, Summary: v.Summary, Detail: detail})

	w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)") // fake banner: the honeypot's whole purpose is to look like a target
	switch {
	case reAdmin.MatchString(path):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodPost {
			time.Sleep(150 * time.Millisecond) // a failed login feels real and slows brute force down
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "<html><body>Invalid username or password.</body></html>")
			return
		}
		fmt.Fprint(w, loginPage)
	case reSensitive.MatchString(path):
		http.Error(w, "403 Forbidden", http.StatusForbidden)
	default:
		http.NotFound(w, r)
	}
}

func NewHTTPServer(addr string, h *HTTPHandler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
}
