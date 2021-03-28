package signkey

import (
	"io"
	"crypto/rand"
	"golang.org/x/crypto/ed25519"
)

// pubkp is internal struct that holds the public-key only key.
type pubkp struct {
	prefix KeyPrefix
	pubkey ed25519.PublicKey
}

// PublicKey returns the base-32 encoded public key.
func (kp *pubkp) PublicKey() (string, error) {
	pk, err := base32Encode(kp.prefix, kp.pubkey)
	if err != nil {
		return "", err
	}
	return string(pk), nil
}

// Secret will always return an error, since only the public key is known.
func (kp *pubkp) Secret() (string, error) {
	return "", PublicKeyKnownOnlyError
}

// Sign will always return an error, since only the public key is known.
func (kp *pubkp) Sign(payload []byte) ([]byte, error) {
	return nil, CannotSignError
}

// Verify payload against a signature.
func (kp *pubkp) Verify(payload []byte, signature []byte) error {
	if !ed25519.Verify(kp.pubkey, payload, signature) {
		return InvalidSignatureError
	}
	return nil
}

// Reset overwrite the public key with random data and erase the prefix byte.
func (kp *pubkp) Reset() {
	kp.prefix = '0'
	io.ReadFull(rand.Reader, kp.pubkey)
}