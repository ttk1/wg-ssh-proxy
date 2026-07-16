// Package keygen generates WireGuard-compatible keys for hosts without a wg
// install (typically the Windows client). The three functions mirror
// wg(8)'s genkey / pubkey / genpsk: 32-byte keys, base64 standard encoding,
// interchangeable with keys made by wg itself.
package keygen

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// GeneratePrivateKey returns a fresh Curve25519 private key (wg genkey).
// Clamping is applied before encoding so the stored key is bit-identical in
// form to wg genkey output (X25519 would clamp again during use anyway).
func GeneratePrivateKey() (string, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

// PublicKey derives the public key of a base64 private key (wg pubkey).
func PublicKey(privateKey string) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("invalid base64 private key: %v", err)
	}
	if len(priv) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes, got %d", len(priv))
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// GeneratePresharedKey returns 32 random bytes (wg genpsk).
func GeneratePresharedKey() (string, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), nil
}
