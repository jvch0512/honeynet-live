// Package honeypot implements low-interaction HTTP and Telnet honeypots and the rules that classify what hits them.
// Nothing here executes attacker input: responses are canned and commands are only parsed and logged.
package honeypot

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/jvch0512/honeynet-live/internal/events"
)

type Verdict struct {
	Kind     events.Kind
	Severity int
	Summary  string
}

var (
	reTraversal = regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e|%252e)`)
	reSQLi      = regexp.MustCompile(`(?i)(union\s+select|or\s+1=1|'\s*or\s*'|sleep\(\d|information_schema|--\s*$|;\s*drop\s)`)
	reXSS       = regexp.MustCompile(`(?i)(<script|javascript:|onerror\s*=)`)
	reCmdInj    = regexp.MustCompile("(?i)(;|\\||`|\\$\\()\\s*(cat|id|wget|curl|nc|bash|sh|ping)\\b")
	reLog4j     = regexp.MustCompile(`(?i)\$\{jndi:`)
	reScannerUA = regexp.MustCompile(`(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|acunetix|nessus)`)
	reSensitive = regexp.MustCompile(`(?i)(/\.env|/\.git/|/wp-config|/config\.php|/\.aws/|/id_rsa|/backup\.(zip|sql|tar)|/phpinfo|/server-status|/actuator)`)
	reAdmin     = regexp.MustCompile(`(?i)(/wp-login\.php|/xmlrpc\.php|/admin|/phpmyadmin|/manager/html|/login)`)
)

// ClassifyHTTP decides what an HTTP request is. Order matters: the most dangerous match wins.
func ClassifyHTTP(method, rawURL, userAgent, body string) Verdict {
	decoded, err := url.QueryUnescape(rawURL)
	if err != nil {
		decoded = rawURL
	}
	hay := decoded + " " + body
	switch {
	case reLog4j.MatchString(hay) || reLog4j.MatchString(userAgent):
		return Verdict{events.Exploit, 4, "Log4Shell JNDI injection attempt"}
	case reCmdInj.MatchString(hay):
		return Verdict{events.Exploit, 4, "Command injection attempt"}
	case reTraversal.MatchString(rawURL) || reTraversal.MatchString(decoded):
		return Verdict{events.Exploit, 3, "Path traversal attempt"}
	case reSQLi.MatchString(hay):
		return Verdict{events.Exploit, 3, "SQL injection attempt"}
	case reXSS.MatchString(hay):
		return Verdict{events.Exploit, 2, "Cross-site scripting probe"}
	case method == "POST" && reAdmin.MatchString(decoded):
		return Verdict{events.BruteForce, 3, "Login attempt against a fake admin panel"}
	case reSensitive.MatchString(decoded):
		return Verdict{events.Scan, 3, "Hunt for sensitive files and secrets"}
	case reScannerUA.MatchString(userAgent):
		return Verdict{events.Scan, 2, "Automated scanner detected by user agent"}
	case reAdmin.MatchString(decoded):
		return Verdict{events.Probe, 2, "Visit to a fake admin interface"}
	}
	return Verdict{events.Probe, 1, "Request to a path that does not exist"}
}

var reURL = regexp.MustCompile(`(?i)\bhttps?://[^\s'"<>;|&]+`)

// ParseShell splits a pasted command line and reports what a defender should know.
func ParseShell(line string) Verdict {
	l := strings.ToLower(line)
	switch {
	case (strings.Contains(l, "wget ") || strings.Contains(l, "curl ") || strings.Contains(l, "tftp ")) && reURL.MatchString(line):
		return Verdict{events.Malware, 4, "Attempt to download a payload"}
	case strings.Contains(l, "chmod +x") || strings.Contains(l, "chmod 777"):
		return Verdict{events.Command, 3, "Making a dropped file executable"}
	case strings.Contains(l, "/etc/passwd") || strings.Contains(l, "/etc/shadow"):
		return Verdict{events.Command, 3, "Reading account databases"}
	case strings.Contains(l, "crontab") || strings.Contains(l, "authorized_keys") || strings.Contains(l, "rc.local"):
		return Verdict{events.Command, 4, "Trying to establish persistence"}
	case strings.Contains(l, "uname") || strings.HasPrefix(l, "whoami") || strings.HasPrefix(l, "id") || strings.Contains(l, "cat /proc/cpuinfo") || strings.Contains(l, "ifconfig"):
		return Verdict{events.Command, 2, "System reconnaissance"}
	case strings.Contains(l, "rm -rf") || strings.Contains(l, "history -c"):
		return Verdict{events.Command, 3, "Covering tracks"}
	}
	return Verdict{events.Command, 1, "Shell command"}
}

// ExtractURL returns the first URL in the line, defanged, so it is safe to display and share.
func ExtractURL(line string) string {
	m := reURL.FindString(line)
	if m == "" {
		return ""
	}
	return Defang(m)
}

func Defang(s string) string {
	s = strings.Replace(s, "http", "hxxp", 1)
	return strings.ReplaceAll(s, ".", "[.]")
}
