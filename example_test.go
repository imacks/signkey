package signkey_test

import (
	"fmt"
	"io"
	"os"
	"github.com/imacks/signkey"
)

// ExampleKey_Verify demonstrates the general process of creating a secret, marshaling and 
// unmarshaling of the public key, and signature verification.
func ExampleKey_Verify() {
	// create a key that contains the secret
	key, _ := signkey.NewKey(signkey.UserKeyPrefix)

	// demonstrates marshaling the public key to string, and then 
	// unmarshal back to key (public type).
	pubkeyStr, _ := key.PublicKey()
	pubkey, _ := signkey.FromPublicKey(pubkeyStr)
	
	// your payload message and its signature
	message := []byte("hello world")
	signature, _ := key.Sign(message)
	
	// use the public key to verify that the signature and message matches
	err := pubkey.Verify(message, signature)
	if signkey.IsInvalidSignature(err) {
		fmt.Printf("invalid signature\n")
	} else {
		fmt.Printf("good signature\n")
	}

	// what happens if the message was altered?
	badMessage := []byte("evil code")
	err2 := pubkey.Verify(badMessage, signature)
	if signkey.IsInvalidSignature(err2) {
		fmt.Printf("invalid signature\n")
	} else {
		fmt.Printf("good signature\n")
	}

	// Output:
	// good signature
	// invalid signature
}

// ExampleFromRawSecret demonstrates creating a key from an alternative source of entropy.
func ExampleFromRawSecret() {
	// use /dev/urandom to populate rawSeed with entropy data.
	// note that rawSeed must be exactly signkey.SecretSize long.
	ef, err := os.Open("/dev/urandom")
	if err != nil {
		panic(err)
	}
	var rawSeed [signkey.SecretSize]byte
	_, err = io.ReadFull(ef, rawSeed[:])
	if err != nil {
		panic(err)
	}

	// create the key using rawSeed
	key, err := signkey.FromRawSecret(signkey.UserKeyPrefix, rawSeed[:])
	if err != nil {
		panic(err)
	}

	// show that signature verification works
	message := []byte("hello world")
	signature, _ := key.Sign(message)
	err = key.Verify(message, signature)
	if signkey.IsInvalidSignature(err) {
		fmt.Printf("invalid signature\n")
	} else {
		fmt.Printf("good signature\n")
	}

	// Output:
	// good signature
}