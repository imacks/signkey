SignKey
=======
Signature verification based on [Ed25519](https://ed25519.cr.yp.to/).

If you are interested in a CLI utility, go to the `signutil` directory.

Quick start
-----------
This package can create a key, sign and verify signatures. It does not concern itself with the 
actual content being signed.

```golang
// other key types are available, only difference is the prefix
key, _ := signkey.NewKey(signkey.UserKeyPrefix)

// serialize the public key and secret
// you need to keep the secret...secret!
pubkeyStr, _ := key.PublicKey()
secretStr, _ := key.Secret()

// deserialize to a new key instance using the secret
// you can sign AND verify data
key2, _ := signkey.FromSecret(secretStr)
data := []byte("howdy partner")
sig, _ := key2.Sign(data)
err := key2.Verify(data, sig)

// now imagine your friend knows your public key.
// we pass sig and data to your friend...

// deserialize to a new key using the public key.
// this new key can only do verification.
key3, _ := signkey.FromPublicKey(pubkeyStr)
err3 := key3.Verify(data, sig)
if signkey.IsInvalidSignature(err3) {
    panic("bad signature!")
}

// now your friend is sure that `data` came from you.
```

Public key and secret
---------------------
Both are serialized to base32 encoded string (2-7, A-Z).


Source of entropy
-----------------
The NewKey method uses `rand.Reader` as its source of entropy. You can create a key 
with custom entropy source by using FromRawSecret instead. Prepopulate the raw secret 
with your random data that is 32 bytes long.

```golang
var rawSecret [signkey.SecretSize]byte
_, err := io.ReadFull(rand.Reader, rawSecret[:])
key, _ := signkey.FromRawSecret(UserKeyPrefix, rawSecret)
```
