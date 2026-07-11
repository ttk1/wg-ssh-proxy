// wg-ssh-proxy is an SSH ProxyCommand that reaches sshd over an in-process
// WireGuard tunnel (wireguard-go tun/netstack). stdout carries the SSH
// byte stream; all diagnostics go to stderr.
//
// Exit codes: 0 success, 1 connection failure, 2 configuration error.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"github.com/ttk1/wg-ssh-proxy/internal/config"
	"github.com/ttk1/wg-ssh-proxy/internal/pipe"
	"github.com/ttk1/wg-ssh-proxy/internal/tunnel"
)

const dialTimeout = 15 * time.Second

func main() {
	log.SetFlags(0)
	log.SetPrefix("wg-ssh-proxy: ")
	configPath := flag.String("config", config.DefaultPath(), "path to config file")
	verbose := flag.Bool("v", false, "log WireGuard internals to stderr")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Print(err)
		os.Exit(2)
	}

	tun, err := tunnel.Start(cfg, *verbose)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	defer tun.Close()

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	conn, err := tun.DialContext(ctx, cfg.Target.String())
	cancel()
	if err != nil {
		if !tun.HandshakeDone() {
			log.Printf("no WireGuard handshake with %s (check keys, Endpoint, outbound UDP): %v", cfg.Endpoint, err)
		} else {
			log.Printf("handshake OK but connect to %s failed (check Target / sshd): %v", cfg.Target, err)
		}
		os.Exit(1)
	}

	if err := pipe.Run(conn, os.Stdin, os.Stdout); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
