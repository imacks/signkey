package signkey

import "errors"

var (
	// CannotSignError is returned if key cannot be used to sign.
	CannotSignError          = errors.New("key cannot be used to sign")
	// InvalidChecksumError is returned if checksum is invalid.
	InvalidChecksumError     = errors.New("checksum is invalid")
	// InvalidEncodingError is returned if key cannot be decoded.
	InvalidEncodingError     = errors.New("invalid key encoding")
	// InvalidKeyPrefixError is returned if key prefix byte is invalid.
	InvalidKeyPrefixError    = errors.New("invalid key prefix byte")
	// InvalidSecretLengthError is returned if secret size is invalid.
	InvalidSecretLengthError = errors.New("invalid secret size")
	// InvalidSecretError is returned if secret is invalid.
	InvalidSecretError       = errors.New("invalid secret")
	// InvalidSignatureError is returned if signature is invalid.
	InvalidSignatureError    = errors.New("invalid signature")
	// InvalidPublicKeyError is returned if public key is invalid.
	InvalidPublicKeyError    = errors.New("invalid public key")
	// PublicKeyKnownOnlyError is returned if only public key is known.
	PublicKeyKnownOnlyError  = errors.New("only public key is known")
)

// IsInvalidSignature returns true if err is InvalidSignatureError.
func IsInvalidSignature(err error) bool {
	if err == InvalidSignatureError {
		return true
	}
	return false
}