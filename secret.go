package signkey

import (
	"bytes"
	"io"
	"crypto/rand"
	"golang.org/x/crypto/ed25519"
)

// SecretSize is ed25519 seed size.
const SecretSize = ed25519.SeedSize

// secretkp is the internal struct for a keypair using seed.
type secretkp struct {
	seed []byte
}

// Secret returns the base-32 encoded secret.
func (kp *secretkp) Secret() (string, error) {
	return string(kp.seed), nil
}

// PublicKey returns the base-32 encoded public key.
func (kp *secretkp) PublicKey() (string, error) {
	public, raw, err := base32DecodeSecret(kp.seed)
	if err != nil {
		return "", err
	}

	pub, _, err := ed25519.GenerateKey(bytes.NewReader(raw))
	if err != nil {
		return "", err
	}

	pk, err := base32Encode(public, pub)
	if err != nil {
		return "", err
	}

	return string(pk), nil
}

// Sign the payload with the private key.
func (kp *secretkp) Sign(payload []byte) ([]byte, error) {
	_, priv, err := kp.keys()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, payload), nil
}

// Verify the payload against a signature, using the public key.
func (kp *secretkp) Verify(payload []byte, sig []byte) error {
	pub, _, err := kp.keys()
	if err != nil {
		return err
	}

	if !ed25519.Verify(pub, payload, sig) {
		return InvalidSignatureError
	}
	return nil
}

// Reset overwrite the secret with random data.
func (kp *secretkp) Reset() {
	io.ReadFull(rand.Reader, kp.seed)
	kp.seed = nil
}

// rawSeed return the raw, decoded 64 byte seed.
func (kp *secretkp) rawSeed() ([]byte, error) {
	_, raw, err := base32DecodeSecret(kp.seed)
	return raw, err
}

// keys return a 32 byte public key and a 64 byte private key utilizing the seed.
func (kp *secretkp) keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	raw, err := kp.rawSeed()
	if err != nil {
		return nil, nil, err
	}
	return ed25519.GenerateKey(bytes.NewReader(raw))
}