package signkey

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"crypto/rand"
)

func TestEncode(t *testing.T) {
	var rawKey [32]byte

	_, err := io.ReadFull(rand.Reader, rawKey[:])
	if err != nil {
		t.Fatalf("Unexpected error reading from crypto/rand: %v", err)
	}

	_, err = base32Encode(UserKeyPrefix, rawKey[:])
	if err != nil {
		t.Fatalf("Unexpected error from base32Encode: %v", err)
	}

	str, err := base32Encode(22<<3, rawKey[:])
	if err == nil {
		t.Fatal("Expected an error from base32Encode but received nil")
	}
	if str != nil {
		t.Fatalf("Expected empty string from base32Encode: got %s", str)
	}
}

func TestDecode(t *testing.T) {
	var rawKey [32]byte

	_, err := io.ReadFull(rand.Reader, rawKey[:])
	if err != nil {
		t.Fatalf("Unexpected error reading from crypto/rand: %v", err)
	}

	str, err := base32Encode(UserKeyPrefix, rawKey[:])
	if err != nil {
		t.Fatalf("Unexpected error from base32Encode: %v", err)
	}

	_, decoded, err := base32DecodeWithPrefix(str)
	if err != nil {
		t.Fatalf("Unexpected error from base32DecodeWithPrefix: %v", err)
	}
	if !bytes.Equal(decoded, rawKey[:]) {
		t.Fatalf("Decoded does not match the original")
	}
}

func TestSecret(t *testing.T) {
	var rawKeyShort [16]byte

	_, err := io.ReadFull(rand.Reader, rawKeyShort[:])
	if err != nil {
		t.Fatalf("Unexpected error reading from crypto/rand: %v", err)
	}

	// secrets need to be 64 bytes
	if _, err := base32EncodeSecret(UserKeyPrefix, rawKeyShort[:]); err != InvalidSecretLengthError {
		t.Fatalf("Did not receive InvalidSecretLengthError error, received %v", err)
	}

	// secrets need to be typed with only public types.
	if _, err := base32EncodeSecret(SecretKeyPrefix, rawKeyShort[:]); err != InvalidKeyPrefixError {
		t.Fatalf("Did not receive InvalidKeyPrefixError error, received %v", err)
	}

	var rawSeed [SecretSize]byte

	_, err = io.ReadFull(rand.Reader, rawSeed[:])
	if err != nil {
		t.Fatalf("Unexpected error reading from crypto/rand: %v", err)
	}

	secret, err := base32EncodeSecret(UserKeyPrefix, rawSeed[:])
	if err != nil {
		t.Fatalf("EncodeSeed received an error: %v", err)
	}

	pre, decoded, err := base32DecodeSecret(secret)
	if err != nil {
		t.Fatalf("Unexpected error from base32DecodeSecret: %v", err)
	}
	if pre != UserKeyPrefix {
		t.Fatalf("Expected the prefix to be UserKeyPrefix(%v), got %v", UserKeyPrefix, pre)
	}
	if !bytes.Equal(decoded, rawSeed[:]) {
		t.Fatalf("Decoded seed does not match the original")
	}
}

func TestUserKey(t *testing.T) {
	user, err := NewKey(UserKeyPrefix)
	if err != nil {
		t.Fatalf("Expected non-nil error on NewKey(UserKeyPrefix), received %v", err)
	}
	if user == nil {
		t.Fatal("Expect a non-nil user")
	}

	// Check Public
	public, err := user.PublicKey()
	if err != nil {
		t.Fatalf("Received an error retrieving public key: %v", err)
	}
	if public[0] != 'U' {
		t.Fatalf("Expected a prefix of 'U' but got %c", public[0])
	}
	if KeyType(public) != UserKeyPrefix {
		t.Fatalf("Not a valid public user key")
	}
}

func TestKeyType(t *testing.T) {
	user, _ := NewKey(UserKeyPrefix)
	pub, _ := user.PublicKey()
	if pre := KeyType(pub); pre != UserKeyPrefix {
		t.Fatalf("Expected %s, got %s\n", UserKeyPrefix, pre)
	}

	secret, _ := user.Secret()
	if pre := KeyType(string(secret)); pre != SecretKeyPrefix {
		t.Fatalf("Expected %s, got %s\n", SecretKeyPrefix, pre)
	}

	if pre := KeyType("FOOBAR"); pre != UnknownKeyPrefix {
		t.Fatalf("Expected %s, got %s\n", UnknownKeyPrefix, pre)
	}
}

func TestIsPublic(t *testing.T) {
	user, _ := NewKey(UserKeyPrefix)
	pub, _ := user.PublicKey()
	if !IsPublicKey(pub) {
		t.Fatalf("Expected pub to be a valid public key")
	}

	secret, _ := user.Secret()
	if IsPublicKey(string(secret)) {
		t.Fatalf("Expected seed to not be a valid public key")
	}

	if IsPublicKey("BAD") {
		t.Fatalf("Expected BAD to not be a valid public key")
	}
}

func TestFromPublic(t *testing.T) {
	// Create a User
	user, err := NewKey(UserKeyPrefix)
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateUser, received %v", err)
	}
	if user == nil {
		t.Fatal("Expect a non-nil user")
	}

	// Now create a publickey only KeyPair
	publicKey, err := user.PublicKey()
	if err != nil {
		t.Fatalf("Error retrieving public key from user: %v", err)
	}
	publicKeyClone, _ := user.PublicKey()
	if publicKeyClone != publicKey {
		t.Fatalf("Expected the public keys to match: %q vs %q", publicKeyClone, publicKey)
	}

	pubUser, err := FromPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Error creating public key only user: %v", err)
	}

	publicKey2, err := pubUser.PublicKey()
	if err != nil {
		t.Fatalf("Error retrieving public key from public user: %v", err)
	}
	// Make sure they match
	if publicKey2 != publicKey {
		t.Fatalf("Expected the public keys to match: %q vs %q", publicKey2, publicKey)
	}

	if _, err := pubUser.Secret(); err == nil {
		t.Fatalf("Expected and error trying to get secret")
	}

	data := []byte("all work and no play makes Jack a dull boy")

	// Can't sign..
	if _, err = pubUser.Sign(data); err != CannotSignError {
		t.Fatalf("Expected %v, but got %v", CannotSignError, err)
	}

	// Should be able to verify with pubUser.
	sig, err := user.Sign(data)
	if err != nil {
		t.Fatalf("Unexpected error signing from user: %v", err)
	}

	err = pubUser.Verify(data, sig)
	if err != nil {
		t.Fatalf("Unexpected error verifying signature: %v", err)
	}

	// Create another user to sign and make sure verify fails.
	user2, _ := NewKey(UserKeyPrefix)
	sig, _ = user2.Sign(data)

	err = pubUser.Verify(data, sig)
	if err == nil {
		t.Fatalf("Expected verification to fail.")
	}
}

func TestFromSecret(t *testing.T) {
	user, err := NewKey(UserKeyPrefix)
	if err != nil {
		t.Fatalf("Expected non-nil error on NewKey(UserKeyPrefix), received %v", err)
	}
	if user == nil {
		t.Fatal("Expect a non-nil user")
	}

	data := []byte("all work and no play makes Jack a dull boy")
	sig, err := user.Sign(data)
	if err != nil {
		t.Fatalf("Unexpected error signing from user: %v", err)
	}

	secret, err := user.Secret()
	if err != nil {
		t.Fatalf("Unexpected error retrieving secret: %v", err)
	}
	// Make sure the seed starts with SA
	if !strings.HasPrefix(secret, "SU") {
		t.Fatalf("Expected seed to start with 'SU', go '%s'", secret[:2])
	}

	user2, err := FromSecret(secret)
	if err != nil {
		t.Fatalf("Error recreating user from secret: %v", err)
	}
	if user2 == nil {
		t.Fatal("Expect a non-nil user")
	}
	err = user2.Verify(data, sig)
	if err != nil {
		t.Fatalf("Unexpected error verifying signature: %v", err)
	}
}

func TestFromRawSecret(t *testing.T) {
	user, err := NewKey(UserKeyPrefix)
	if err != nil {
		t.Fatalf("Expected non-nil error on NewKey(UserKeyPrefix), received %v", err)
	}

	se, _ := user.Secret()
	_, raw, _ := base32DecodeSecret([]byte(se))

	user2, err := FromRawSecret(UserKeyPrefix, raw)
	if err != nil {
		t.Fatalf("Expected non-nil error on FromRawSecret, received %v", err)
	}

	s2e, _ := user2.Secret()
	if se != s2e {
		t.Fatalf("Expected the secrets to be the same, got %v vs %v\n", se, s2e)
	}
}

func TestKeyFailures(t *testing.T) {
	var tooshort [8]byte
	if _, err := base32EncodeSecret(UserKeyPrefix, tooshort[:]); err == nil {
		t.Fatal("Expected an error with insufficient rand")
	}

	if _, err := NewKey(PrivateKeyPrefix); err == nil {
		t.Fatal("Expected an error with non-public prefix")
	}

	kpbad := &secretkp{[]byte("SEEDBAD")}
	if _, _, err := kpbad.keys(); err == nil {
		t.Fatal("Expected an error decoding keys with a bad seed")
	}
	if _, err := kpbad.PublicKey(); err == nil {
		t.Fatal("Expected an error getting PublicKey from KP with a bad seed")
	}
	if _, err := kpbad.Sign([]byte("ok")); err == nil {
		t.Fatal("Expected an error from Sign from KP with a bad seed")
	}
}

func TestBadDecode(t *testing.T) {
	if _, err := base32Decode([]byte("foo!")); err == nil {
		t.Fatal("Expected an error decoding non-base32")
	}
	if _, err := base32Decode([]byte("OK")); err == nil {
		t.Fatal("Expected an error decoding a too short string")
	}

	// Create invalid checksum
	user, _ := NewKey(UserKeyPrefix)
	pkey, _ := user.PublicKey()
	bpkey := []byte(pkey)
	bpkey[len(pkey)-1] = '0'
	bpkey[len(pkey)-2] = '0'

	if _, err := base32Decode(bpkey); err == nil {
		t.Fatal("Expected error on decode with bad checksum")
	}

	p, _, err := base32DecodeWithPrefix([]byte(pkey))
	if err != nil {
		t.Fatal("Unexpected error on base32DecodeWithPrefix")
	}
	if p != UserKeyPrefix {
		t.Fatal("Expected UserKeyPrefix")
	}
	if _, _, err := base32DecodeWithPrefix(bpkey); err == nil {
		t.Fatal("Expected error on base32DecodeWithPrefix with bad checksum")
	}
	// Seed version
	if _, _, err := base32DecodeSecret(bpkey); err == nil {
		t.Fatal("Expected error on base32DecodeSecret with bad checksum")
	}
	if _, _, err := base32DecodeSecret([]byte(pkey)); err == nil {
		t.Fatal("Expected error on base32DecodeSecret with bad secret type")
	}

	secret, _ := user.Secret()
	bsecret := []byte(secret)
	bsecret[1] = 'S'

	if _, _, err := base32DecodeSecret(bsecret); err == nil {
		t.Fatal("Expected error on base32DecodeSecret with bad prefix type")
	}
	if _, err := FromSecret(string(bsecret)); err == nil {
		t.Fatal("Expected error on FromSecret with bad prefix type")
	}

	if _, err := FromPublicKey(string(bpkey)); err == nil {
		t.Fatal("Expected error on FromPublicKey with bad checksum")
	}
	if _, err := FromPublicKey(string(secret)); err == nil {
		t.Fatal("Expected error on FromPublicKey with bad checksum")
	}
}

func TestReset(t *testing.T) {
	user, err := NewKey(UserKeyPrefix)
	if err != nil {
		t.Fatalf("Expected non-nil error on NewKey(UserKeyPrefix), received %v", err)
	}

	pubKey, err := user.PublicKey()
	if err != nil {
		t.Fatalf("Received an error retrieving public key: %v", err)
	}

	seed := user.(*secretkp).seed

	// Copy so we know the original
	copy := append([]byte{}, seed...)
	user.Reset()

	// Make sure new seed is nil
	if wiped := user.(*secretkp).seed; wiped != nil {
		t.Fatalf("Expected the seed to be nil, got %q", wiped)
	}

	// Make sure the original seed is not equal to the seed in memory.
	if bytes.Equal(seed, copy) {
		t.Fatalf("Expected the memory for the seed to be randomized")
	}

	// Now test public
	user, err = FromPublicKey(pubKey)
	if err != nil {
		t.Fatalf("Received an error create key from PublicKey: %v", err)
	}

	edPub := user.(*pubkp).pubkey
	// Copy so we know the original
	copy = append([]byte{}, edPub...)

	user.Reset()

	// First check pre was changed
	if user.(*pubkp).prefix != '0' {
		t.Fatalf("Expected prefix to be changed")
	}

	// Make sure the original key is not equal to the one in memory.
	if bytes.Equal(edPub, copy) {
		t.Fatalf("Expected the memory for the pubkey to be randomized")
	}
}