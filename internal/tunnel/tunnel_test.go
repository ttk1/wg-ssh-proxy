package tunnel

import (
	"strings"
	"testing"

	"github.com/ttk1/wg-ssh-proxy/internal/config"
)

// ipcConfig must scope allowed_ip to the Target host alone: cryptokey
// routing is the receive-side boundary for what the peer may inject.
func TestIpcConfigLimitsAllowedIPToTarget(t *testing.T) {
	cfg, err := config.Parse(`
PrivateKey    = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address       = 10.0.0.2/32
PeerPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint      = 192.0.2.1:51820
Target        = 10.0.0.1:22
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ipc, err := ipcConfig(cfg)
	if err != nil {
		t.Fatalf("ipcConfig: %v", err)
	}

	var allowed []string
	for _, l := range strings.Split(strings.TrimSpace(ipc), "\n") {
		if strings.HasPrefix(l, "allowed_ip=") {
			allowed = append(allowed, l)
		}
	}
	if len(allowed) != 1 || allowed[0] != "allowed_ip=10.0.0.1/32" {
		t.Errorf("allowed_ip lines = %v, want exactly [allowed_ip=10.0.0.1/32]", allowed)
	}
	if !strings.Contains(ipc, "endpoint=192.0.2.1:51820\n") {
		t.Errorf("endpoint line missing or wrong:\n%s", ipc)
	}
	if strings.Contains(ipc, "preshared_key=") {
		t.Errorf("preshared_key present without PresharedKey set:\n%s", ipc)
	}
}
