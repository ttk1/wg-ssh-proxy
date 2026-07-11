// Package tunnel runs an in-process WireGuard interface on a userspace
// network stack (wireguard-go tun/netstack). No TUN device, OS route or
// firewall rule is created; only connections dialed through Tunnel ever
// enter the VPN.
package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/ttk1/wg-ssh-proxy/internal/config"
)

type Tunnel struct {
	dev  *device.Device
	tnet *netstack.Net
}

// Start creates the userspace stack and brings the WireGuard device up.
// The handshake itself happens lazily on the first Dial. With verbose set,
// wireguard-go's internal log (handshake retries etc.) goes to stderr.
func Start(cfg *config.Config, verbose bool) (*Tunnel, error) {
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.Address}, nil, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create netstack: %v", err)
	}
	logLevel := device.LogLevelError
	if verbose {
		logLevel = device.LogLevelVerbose
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(logLevel, "wireguard: "))

	ipc, err := ipcConfig(cfg)
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure device: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device up: %v", err)
	}
	return &Tunnel{dev: dev, tnet: tnet}, nil
}

// ipcConfig renders the device configuration in wireguard-go's IPC format.
func ipcConfig(cfg *config.Config) (string, error) {
	// wireguard-go does not resolve hostnames in "endpoint="; do it here.
	addr, err := net.ResolveUDPAddr("udp", cfg.Endpoint)
	if err != nil {
		return "", fmt.Errorf("resolve endpoint %s: %v", cfg.Endpoint, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", cfg.PrivateKey.Hex())
	fmt.Fprintf(&b, "public_key=%s\n", cfg.PeerPublicKey.Hex())
	if cfg.PresharedKey != nil {
		fmt.Fprintf(&b, "preshared_key=%s\n", cfg.PresharedKey.Hex())
	}
	ap := addr.AddrPort()
	fmt.Fprintf(&b, "endpoint=%s\n", netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
	if cfg.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", cfg.Keepalive)
	}
	// Cryptokey routing: accept tunneled packets only if their inner source
	// address is the Target host. Everything this process dials goes to
	// Target anyway, so a wider allowed_ip (0.0.0.0/0) would only widen
	// what a compromised peer could inject into the local netstack.
	target := cfg.Target.Addr()
	fmt.Fprintf(&b, "allowed_ip=%s\n", netip.PrefixFrom(target, target.BitLen()))
	return b.String(), nil
}

// DialContext opens a TCP connection to addr through the tunnel.
func (t *Tunnel) DialContext(ctx context.Context, addr string) (net.Conn, error) {
	return t.tnet.DialContext(ctx, "tcp", addr)
}

// HandshakeDone reports whether a WireGuard handshake has completed,
// to tell "peer unreachable" apart from "target port unreachable".
func (t *Tunnel) HandshakeDone() bool {
	status, err := t.dev.IpcGet()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok && v != "0" {
			return true
		}
	}
	return false
}

func (t *Tunnel) Close() {
	t.dev.Close()
}
