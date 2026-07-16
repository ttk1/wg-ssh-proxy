// wg-ssh-proxy is an SSH ProxyCommand that reaches sshd over an in-process
// WireGuard tunnel (wireguard-go tun/netstack). stdout carries the SSH
// byte stream; all diagnostics go to stderr.
//
// The genkey, pubkey and genpsk subcommands mirror the wg(8) commands of the
// same name (base64 keys, one per line), for hosts without a wg install.
//
// Exit codes: 0 success, 1 runtime failure, 2 configuration or usage error.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ttk1/wg-ssh-proxy/internal/config"
	"github.com/ttk1/wg-ssh-proxy/internal/keygen"
	"github.com/ttk1/wg-ssh-proxy/internal/pipe"
	"github.com/ttk1/wg-ssh-proxy/internal/tunnel"
)

const dialTimeout = 15 * time.Second

func main() {
	log.SetFlags(0)
	log.SetPrefix("wg-ssh-proxy: ")

	// Key subcommands are dispatched before flag parsing so that the bare
	// flags-only invocation used as the SSH ProxyCommand stays unchanged.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "genkey", "pubkey", "genpsk":
			os.Exit(runKeyCommand(os.Args[1], os.Args[2:]))
		}
	}

	configPath := flag.String("config", config.DefaultPath(), "path to config file")
	verbose := flag.Bool("v", false, "log WireGuard internals to stderr")
	flag.Parse()
	// A leftover positional argument is a typo (e.g. "genkye"); running the
	// proxy instead would just hang waiting on stdin.
	if flag.NArg() > 0 {
		log.Printf("unknown command %q (subcommands: genkey, pubkey, genpsk)", flag.Arg(0))
		os.Exit(2)
	}

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

// runKeyCommand implements the wg(8)-compatible key subcommands and returns
// the exit code. genkey and genpsk print a fresh key; pubkey reads a private
// key from stdin (never from an argument, which would leak it into the
// process list) and prints its public key.
func runKeyCommand(name string, args []string) int {
	if len(args) > 0 {
		log.Printf("%s takes no arguments", name)
		return 2
	}
	var out string
	var err error
	switch name {
	case "genkey":
		out, err = keygen.GeneratePrivateKey()
	case "genpsk":
		out, err = keygen.GeneratePresharedKey()
	case "pubkey":
		in, rerr := io.ReadAll(os.Stdin)
		if rerr != nil {
			log.Printf("pubkey: read stdin: %v", rerr)
			return 1
		}
		// Trim a UTF-8 BOM too: Windows editors like to prepend one.
		out, err = keygen.PublicKey(strings.TrimSpace(strings.TrimPrefix(string(in), "\xef\xbb\xbf")))
	}
	if err != nil {
		log.Printf("%s: %v", name, err)
		return 1
	}
	fmt.Println(out)
	return 0
}
