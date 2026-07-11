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
	Address       netip.Addr // client's WireGuard IP
	PeerPublicKey Key
	PresharedKey  *Key   // optional
	Endpoint      string // server "host:port" (hostname allowed)
	Target        string // dial destination "ip:port" inside the tunnel
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
	if err := checkPermissions(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
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
func checkPermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s has mode %04o; it holds a private key, run: chmod 600 %s", path, perm, path)
	}
	return nil
}

// Parse parses the configuration text and validates all fields.
func Parse(text string) (*Config, error) {
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
		var prefix netip.Prefix
		if prefix, err = netip.ParsePrefix(value); err == nil {
			c.Address = prefix.Addr()
		}
	case "Endpoint":
		_, _, err = net.SplitHostPort(value)
		c.Endpoint = value
	case "Target":
		var ap netip.AddrPort
		if ap, err = netip.ParseAddrPort(value); err == nil {
			c.Target = ap.String()
		}
	case "MTU":
		c.MTU, err = strconv.Atoi(value)
	case "PersistentKeepalive":
		c.Keepalive, err = strconv.Atoi(value)
	default:
		err = fmt.Errorf("unknown key")
	}
	return err
}

func (c *Config) validate(seen map[string]bool) error {
	for _, key := range []string{"PrivateKey", "Address", "PeerPublicKey", "Endpoint", "Target"} {
		if !seen[key] {
			return fmt.Errorf("missing required key %q", key)
		}
	}
	if c.MTU < 576 || c.MTU > 65535 {
		return fmt.Errorf("MTU %d out of range", c.MTU)
	}
	if c.Keepalive < 0 {
		return fmt.Errorf("PersistentKeepalive must be >= 0")
	}
	return nil
}
