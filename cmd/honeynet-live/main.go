package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/jvch0512/honeynet-live/internal/attacker"
	"github.com/jvch0512/honeynet-live/internal/events"
	"github.com/jvch0512/honeynet-live/internal/honeypot"
	"github.com/jvch0512/honeynet-live/internal/server"
)

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func main() {
	httpAddr := flag.String("http", "127.0.0.1:8081", "HTTP honeypot address")
	telnetAddr := flag.String("telnet", "127.0.0.1:2323", "Telnet honeypot address")
	dashAddr := flag.String("dash", "127.0.0.1:8095", "dashboard address")
	demo := flag.Bool("demo", false, "run the built-in attack simulator (trusts X-Forwarded-For and PROXY headers, loopback only)")
	every := flag.Duration("every", 900*time.Millisecond, "simulator interval")
	seed := flag.Int64("seed", 42, "simulator seed")
	risk := flag.Bool("i-understand-the-risk", false, "allow listening on non-loopback addresses")
	flag.Parse()

	for _, a := range []string{*httpAddr, *telnetAddr, *dashAddr} {
		if !isLoopback(a) && !*risk {
			log.Fatalf("refusing to listen on %s: honeypots attract real attackers. Use -i-understand-the-risk after reading the README", a)
		}
	}
	if *demo && (!isLoopback(*httpAddr) || !isLoopback(*telnetAddr)) {
		log.Fatal("-demo trusts client-supplied source addresses and must stay on loopback")
	}

	store := events.NewStore()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	hp := honeypot.NewHTTPServer(*httpAddr, &honeypot.HTTPHandler{Store: store, TrustXFF: *demo})
	go func() {
		if err := hp.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	ln, err := net.Listen("tcp", *telnetAddr)
	if err != nil {
		log.Fatal(err)
	}
	go (&honeypot.Telnet{Store: store, ProxyProtocol: *demo}).Serve(ctx, ln)

	if *demo {
		go attacker.New(*httpAddr, *telnetAddr, *seed).Run(ctx, *every)
	}
	dash := &http.Server{Addr: *dashAddr, Handler: (&server.Server{Store: store}).Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sc, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		dash.Shutdown(sc)
		hp.Shutdown(sc)
	}()
	fmt.Printf("Honeynet Live: dashboard http://%s | http honeypot %s | telnet honeypot %s | demo=%v\n", *dashAddr, *httpAddr, *telnetAddr, *demo)
	if err := dash.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
