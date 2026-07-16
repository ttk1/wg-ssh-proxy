package keygen

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("not valid base64: %v", err)
	}
	return b
}

func TestGeneratePrivateKey(t *testing.T) {
	s1, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	k := decode(t, s1)
	if len(k) != 32 {
		t.Fatalf("got %d bytes, want 32", len(k))
	}
	// WireGuard clamping: low 3 bits of k[0] cleared, top bit of k[31]
	// cleared, second-highest bit of k[31] set.
	if k[0]&7 != 0 || k[31]&128 != 0 || k[31]&64 == 0 {
		t.Fatalf("key not clamped: k[0]=%08b k[31]=%08b", k[0], k[31])
	}
	s2, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if s1 == s2 {
		t.Fatal("two generated keys are identical")
	}
}

// TestPublicKeyRFC7748 checks the derivation against the X25519 test vector
// from RFC 7748 section 6.1 (Alice's keypair).
func TestPublicKeyRFC7748(t *testing.T) {
	priv, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	const wantHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"

	got, err := PublicKey(base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	if gotHex := hex.EncodeToString(decode(t, got)); gotHex != wantHex {
		t.Fatalf("public key = %s, want %s", gotHex, wantHex)
	}
}

func TestPublicKeyRejectsBadInput(t *testing.T) {
	for _, in := range []string{
		"",
		"not base64 !!!",
		base64.StdEncoding.EncodeToString(make([]byte, 31)), // wrong length
	} {
		if _, err := PublicKey(in); err == nil {
			t.Errorf("PublicKey(%q): expected error", in)
		}
	}
}

func TestGeneratePresharedKey(t *testing.T) {
	s1, err := GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(decode(t, s1)) != 32 {
		t.Fatal("psk is not 32 bytes")
	}
	s2, err := GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	if s1 == s2 {
		t.Fatal("two generated PSKs are identical")
	}
}
