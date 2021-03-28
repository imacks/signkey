package signkey

// KeyPrefix represents the key type.
type KeyPrefix byte

const (
	// SecretKeyPrefix denotes secret key.
	SecretKeyPrefix KeyPrefix = 18 << 3 // base32 S
	// PrivateKeyPrefix denotes private key.
	PrivateKeyPrefix KeyPrefix = 15 << 3 // base32 P
	// UserKeyPrefix denotes user key.
	UserKeyPrefix KeyPrefix = 20 << 3 // base32 U
	// UnknownKeyPrefix denotes unknown key type.
	UnknownKeyPrefix KeyPrefix = 23 << 3 // base32 X
)

func (p KeyPrefix) String() string {
	switch p {
	case UserKeyPrefix:
		return "user"
	case SecretKeyPrefix:
		return "secret"
	case PrivateKeyPrefix:
		return "private"
	}
	return "unknown"
}

// isUnknownKeyPrefix returns true if the prefix is unknown.
func isUnknownKeyPrefix(p KeyPrefix) bool {
	switch p {
	case UserKeyPrefix, SecretKeyPrefix, PrivateKeyPrefix:
		return false
	}
	return true
}

// isPublicKeyPrefix returns true if the prefix is a public-type key.
// Right now the only non-public type keys are: private, secret.
func isPublicKeyPrefix(p KeyPrefix) bool {
	switch p {
	case UserKeyPrefix:
		return true
	}
	return false
}