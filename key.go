package signkey

import (
	"io"
	"crypto/rand"
)

// Key is abstract interface for a key.
type Key interface {
	// Secret returns the base-32 encoded secret.
	Secret() (string, error)
	// PublicKey returns the base-32 encoded public key.
	PublicKey() (string, error)
	// Sign calculates the signature of input, using secret.
	Sign(input []byte) ([]byte, error)
	// Verify input against signature sig, using public key.
	Verify(input []byte, sig []byte) error
	// Reset overwrites internal data with random data.
	Reset()
}

// NewKey creates a new key, using the key prefix specified.
// This function uses rand.Reader as its source of entropy. If you want to specify 
// a custom entropy source, use the FromRawSecret function instead.
func NewKey(prefix KeyPrefix) (Key, error) {
	var rawSeed [32]byte

	_, err := io.ReadFull(rand.Reader, rawSeed[:])
	if err != nil {
		return nil, err
	}

	seed, err := base32EncodeSecret(prefix, rawSeed[:])
	if err != nil {
		return nil, err
	}

	return &secretkp{seed}, nil
}

// FromPublicKey unmarshals a key using the public key specified. This key 
// can be used to verify signatures only.
func FromPublicKey(public string) (Key, error) {
	raw, err := base32Decode([]byte(public))
	if err != nil {
		return nil, err
	}

	pre := KeyPrefix(raw[0])
	if !isPublicKeyPrefix(pre) {
		return nil, InvalidPublicKeyError
	}

	return &pubkp{pre, raw[1:]}, nil
}

// FromSecret unmarshals a key using the secret specified. This key can both 
// sign and verify.
func FromSecret(secret string) (Key, error) {
	_, _, err := base32DecodeSecret([]byte(secret))
	if err != nil {
		return nil, err
	}

	copy := append([]byte{}, secret...)
	return &secretkp{copy}, nil
}

// FromRawSecret is the same as FromSecret, but assumes that the secret provided has 
// already been decoded.
func FromRawSecret(prefix KeyPrefix, rawSecret []byte) (Key, error) {
	secret, err := base32EncodeSecret(prefix, rawSecret)
	if err != nil {
		return nil, err
	}
	return &secretkp{secret}, nil
}