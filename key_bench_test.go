package signkey

import(
	"testing"
	"crypto/rand"
	"encoding/base64"
)

const (
	nonceRawLen = 16
	nonceLen    = 22 // base64.RawURLEncoding.EncodedLen(nonceRawLen)
)

func BenchmarkSign(b *testing.B) {
	data := make([]byte, nonceRawLen)
	nonce := make([]byte, nonceLen)
	rand.Read(data)
	base64.RawURLEncoding.Encode(nonce, data)

	user, err := NewKey(UserKeyPrefix)
	if err != nil {
		b.Fatalf("Error creating user key: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := user.Sign(nonce); err != nil {
			b.Fatalf("Error signing nonce: %v", err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	data := make([]byte, nonceRawLen)
	nonce := make([]byte, nonceLen)
	rand.Read(data)
	base64.RawURLEncoding.Encode(nonce, data)

	user, err := NewKey(UserKeyPrefix)
	if err != nil {
		b.Fatalf("Error creating User key: %v", err)
	}
	sig, err := user.Sign(nonce)
	if err != nil {
		b.Fatalf("Error sigining nonce: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := user.Verify(nonce, sig); err != nil {
			b.Fatalf("Error verifying nonce: %v", err)
		}
	}
}

func BenchmarkPublicVerify(b *testing.B) {
	data := make([]byte, nonceRawLen)
	nonce := make([]byte, nonceLen)
	rand.Read(data)
	base64.RawURLEncoding.Encode(nonce, data)

	user, err := NewKey(UserKeyPrefix)
	if err != nil {
		b.Fatalf("Error creating User key: %v", err)
	}
	sig, err := user.Sign(nonce)
	if err != nil {
		b.Fatalf("Error sigining nonce: %v", err)
	}
	pk, err := user.PublicKey()
	if err != nil {
		b.Fatalf("Could not extract public key from user: %v", err)
	}
	pub, err := FromPublicKey(pk)
	if err != nil {
		b.Fatalf("Could not create public key pair from public key string: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pub.Verify(nonce, sig); err != nil {
			b.Fatalf("Error verifying nonce: %v", err)
		}
	}
}