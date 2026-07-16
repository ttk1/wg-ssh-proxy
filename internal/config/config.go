// Package config loads and validates the wg-ssh-proxy configuration file.
//
// The file contains the client's WireGuard private key, so it must never be
// passed on the command line. Format is "Key = Value" lines; '#' starts a
// comment.
package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const defaultMTU = 1420

// Key is a 32-byte WireGuard key.
type Key [32]byte

// Hex returns the key in the hex encoding expected by wireguard-go's IpcSet.
func (k Key) Hex() string { return hex.EncodeToString(k[:]) }

func parseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("invalid base64: %v", err)
	}
	if len(b) != len(k) {
		return k, fmt.Errorf("key must be %d bytes, got %d", len(k), len(b))
	}
	copy(k[:], b)
	return k, nil
}

// Config is the parsed and validated configuration.
type Config struct {
	PrivateKey    Key
	Address       netip.Addr // client's WireGuard IP (IPv4)
	PeerPublicKey Key
	PresharedKey  *Key           // optional
	Endpoint      string         // server "host:port" (hostname allowed)
	Target        netip.AddrPort // dial destination inside the tunnel (IPv4)
	MTU           int
	Keepalive     int // persistent keepalive seconds, 0 = off
}

// DefaultPath returns ~/.wg-ssh/config (%USERPROFILE%\.wg-ssh\config on Windows).
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".wg-ssh", "config")
}

// Load reads, permission-checks, parses and validates the file at path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// The permission check runs on the opened handle (fstat), so the file
	// that is read is the same one that was checked.
	if err := checkPermissions(f); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return cfg, nil
}

// checkPermissions rejects group/world-accessible config files on Unix.
// On Windows, file modes are not meaningful; protecting %USERPROFILE% is
// left to the default ACLs (best-effort, see README).
func checkPermissions(f *os.File) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s has mode %04o; it holds a private key, run: chmod 600 %s", f.Name(), perm, f.Name())
	}
	return nil
}

// Parse parses the configuration text and validates all fields.
func Parse(text string) (*Config, error) {
	// Windows editors like to prepend a UTF-8 BOM; without this the first
	// line's key would come out as "<BOM>PrivateKey" ("unknown key").
	text = strings.TrimPrefix(text, "\xef\xbb\xbf")
	cfg := &Config{MTU: defaultMTU}
	seen := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected \"Key = Value\"", i+1)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if seen[key] {
			return nil, fmt.Errorf("line %d: duplicate key %q", i+1, key)
		}
		seen[key] = true
		if err := cfg.set(key, value); err != nil {
			return nil, fmt.Errorf("line %d: %s: %v", i+1, key, err)
		}
	}
	return cfg, cfg.validate(seen)
}

func (c *Config) set(key, value string) error {
	var err error
	switch key {
	case "PrivateKey":
		c.PrivateKey, err = parseKey(value)
	case "PeerPublicKey":
		c.PeerPublicKey, err = parseKey(value)
	case "PresharedKey":
		var k Key
		if k, err = parseKey(value); err == nil {
			c.PresharedKey = &k
		}
	case "Address":
		// WireGuard configs usually write "10.0.0.2/32". The prefix length
		// carries no meaning here (the netstack holds just this one address),
		// so a bare "10.0.0.2" is accepted too.
		if strings.Contains(value, "/") {
			var prefix netip.Prefix
			if prefix, err = netip.ParsePrefix(value); err == nil {
				c.Address = prefix.Addr()
			}
		} else {
			c.Address, err = netip.ParseAddr(value)
		}
	case "Endpoint":
		// A hostname is allowed (resolved at tunnel start), so only the
		// shape is checked here. An empty host or a non-numeric/zero port
		// would otherwise surface much later as a cryptic device error or
		// a silent handshake timeout.
		err = checkHostPort(value)
		c.Endpoint = value
	case "Target":
		c.Target, err = netip.ParseAddrPort(value)
	case "MTU":
		c.MTU, err = strconv.Atoi(value)
	case "PersistentKeepalive":
		c.Keepalive, err = strconv.Atoi(value)
	default:
		err = fmt.Errorf("unknown key")
	}
	return err
}

// checkHostPort validates "host:port" with a non-empty host and a numeric
// port in 1..65535.
func checkHostPort(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return err
	}
	if host == "" {
		return fmt.Errorf("missing host in %q", value)
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}

func (c *Config) validate(seen map[string]bool) error {
	for _, key := range []string{"PrivateKey", "Address", "PeerPublicKey", "Endpoint", "Target"} {
		if !seen[key] {
			return fmt.Errorf("missing required key %q", key)
		}
	}
	// The tunnel is IPv4-only. Rejecting IPv6 (including ::ffff: forms) here
	// turns a silent connect failure into a clear config error.
	if !c.Address.Is4() {
		return fmt.Errorf("Address must be IPv4")
	}
	if !c.Target.Addr().Is4() {
		return fmt.Errorf("Target must be IPv4")
	}
	// netip.ParseAddrPort accepts port 0, which would only fail later as an
	// opaque dial error.
	if c.Target.Port() == 0 {
		return fmt.Errorf("Target port must be 1..65535")
	}
	// Dialing the client's own address never leaves the netstack; this is
	// almost certainly the server/client IPs swapped in the config.
	if c.Target.Addr() == c.Address {
		return fmt.Errorf("Target address equals the client Address; it must be the server's WireGuard IP")
	}
	if c.MTU < 576 || c.MTU > 65535 {
		return fmt.Errorf("MTU %d out of range (576..65535)", c.MTU)
	}
	// wireguard-go stores the interval as uint16 seconds.
	if c.Keepalive < 0 || c.Keepalive > 65535 {
		return fmt.Errorf("PersistentKeepalive must be 0..65535")
	}
	return nil
}
