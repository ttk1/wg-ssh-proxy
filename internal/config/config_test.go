package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 32 bytes of zeros in base64; value is irrelevant, only shape is checked.
const testKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

const validConfig = `
# comment
PrivateKey    = ` + testKey + `
Address       = 10.0.0.2/32
PeerPublicKey = ` + testKey + ` # trailing comment
Endpoint      = server.example.com:51820
Target        = 10.0.0.1:22
`

func TestParseValid(t *testing.T) {
	cfg, err := Parse(validConfig)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.Address.String(); got != "10.0.0.2" {
		t.Errorf("Address = %q", got)
	}
	if cfg.Endpoint != "server.example.com:51820" {
		t.Errorf("Endpoint = %q", cfg.Endpoint)
	}
	if got := cfg.Target.String(); got != "10.0.0.1:22" {
		t.Errorf("Target = %q", got)
	}
	if cfg.MTU != 1420 {
		t.Errorf("MTU default = %d, want 1420", cfg.MTU)
	}
	if cfg.PresharedKey != nil || cfg.Keepalive != 0 {
		t.Error("optional fields should be unset")
	}
	if cfg.PrivateKey.Hex() != strings.Repeat("0", 64) {
		t.Errorf("PrivateKey.Hex() = %q", cfg.PrivateKey.Hex())
	}
}

func TestParseOptionalFields(t *testing.T) {
	cfg, err := Parse(validConfig + `
PresharedKey = ` + testKey + `
MTU = 1280
PersistentKeepalive = 25
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.PresharedKey == nil {
		t.Error("PresharedKey not set")
	}
	if cfg.MTU != 1280 || cfg.Keepalive != 25 {
		t.Errorf("MTU = %d, Keepalive = %d", cfg.MTU, cfg.Keepalive)
	}
}

// Address is accepted both as "10.0.0.2/32" (WireGuard style) and bare.
func TestParseAddressWithoutPrefix(t *testing.T) {
	cfg, err := Parse(strings.Replace(validConfig, "10.0.0.2/32", "10.0.0.2", 1))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.Address.String(); got != "10.0.0.2" {
		t.Errorf("Address = %q", got)
	}
}

func TestParseErrors(t *testing.T) {
	drop := func(key string) string {
		var kept []string
		for _, l := range strings.Split(validConfig, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), key) {
				kept = append(kept, l)
			}
		}
		return strings.Join(kept, "\n")
	}
	tests := map[string]string{
		"missing PrivateKey":  drop("PrivateKey"),
		"missing Target":      drop("Target"),
		"bad base64":          drop("PrivateKey") + "\nPrivateKey = not-base64",
		"short key":           drop("PrivateKey") + "\nPrivateKey = AAAA",
		"hostname in Target":  drop("Target") + "\nTarget = server.example.com:22",
		"endpoint no port":    drop("Endpoint") + "\nEndpoint = 192.0.2.1",
		"unknown key":         validConfig + "\nBogus = 1",
		"duplicate key":       validConfig + "\nTarget = 10.0.0.1:22",
		"line without equals": validConfig + "\njunk line",
		"MTU out of range":    validConfig + "\nMTU = 100",
		"negative keepalive":  validConfig + "\nPersistentKeepalive = -1",
		"keepalive too large": validConfig + "\nPersistentKeepalive = 65536",
	}
	for name, text := range tests {
		if _, err := Parse(text); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoadRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission check is Unix-only")
	}
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(validConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "chmod") {
		t.Errorf("expected permission error, got %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("Load with 0600: %v", err)
	}
}
