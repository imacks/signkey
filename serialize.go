package signkey

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
)

// base32Enc is a base32 encoder that does not pad '=='.
var base32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// IsKey returns true only if the encoded data is a valid key.
func IsKey(src []byte) bool {
	_, err := base32Decode(src)
	return err == nil
}

// IsPublicKey returns true if the key is a public public. Only private and secret keys are not public.
func IsPublicKey(src string) bool {
	b, err := base32Decode([]byte(src))
	if err != nil {
		return false
	}
	prefix := KeyPrefix(b[0])
	return isPublicKeyPrefix(prefix)
}

// KeyType returns the key prefix, which indicates the type of key.
func KeyType(src string) KeyPrefix {
	b, err := base32Decode([]byte(src))
	if err != nil {
		return UnknownKeyPrefix
	}

	p := KeyPrefix(b[0])
	if !isUnknownKeyPrefix(p) {
		return p
	}

	// Might be a secret
	b1 := b[0] & 248
	if KeyPrefix(b1) == SecretKeyPrefix {
		return SecretKeyPrefix
	}

	return UnknownKeyPrefix
}

// base32Encode encodes src in base32. The prefix specified will be added at the first position, 
// followed by the payload. CRC16 checksum of what's already written is added next. Finally, the 
// entire blob is base32 encoded.
func base32Encode(prefix KeyPrefix, src []byte) ([]byte, error) {
	if isUnknownKeyPrefix(prefix) {
		return nil, InvalidKeyPrefixError
	}

	var raw bytes.Buffer

	// write prefix byte
	if err := raw.WriteByte(byte(prefix)); err != nil {
		return nil, err
	}

	// write payload
	if _, err := raw.Write(src); err != nil {
		return nil, err
	}

	// calculate and write crc16 checksum
	err := binary.Write(&raw, binary.LittleEndian, crc16(raw.Bytes()))
	if err != nil {
		return nil, err
	}

	data := raw.Bytes()
	buf := make([]byte, base32Enc.EncodedLen(len(data)))
	base32Enc.Encode(buf, data)
	return buf[:], nil
}

// base32EncodeSecret encode a secret. This is the same as base32Encode, but adds 
// the 'S' super-prefix at the first position, followed by the actual prefix and so on.
func base32EncodeSecret(prefix KeyPrefix, src []byte) ([]byte, error) {
	if !isPublicKeyPrefix(prefix) {
		return nil, InvalidKeyPrefixError
	}

	if len(src) != SecretSize {
		return nil, InvalidSecretLengthError
	}

	// in order to make this human printable for both bytes, we need to do a little
	// bit manipulation to setup for base32 encoding which takes 5 bits at a time.
	b1 := byte(SecretKeyPrefix) | (byte(prefix) >> 5)
	b2 := (byte(prefix) & 31) << 3 // 31 = 00011111

	var raw bytes.Buffer

	raw.WriteByte(b1)
	raw.WriteByte(b2)

	// write payload
	if _, err := raw.Write(src); err != nil {
		return nil, err
	}

	// calculate and write crc16 checksum
	err := binary.Write(&raw, binary.LittleEndian, crc16(raw.Bytes()))
	if err != nil {
		return nil, err
	}

	data := raw.Bytes()
	buf := make([]byte, base32Enc.EncodedLen(len(data)))
	base32Enc.Encode(buf, data)
	return buf, nil
}

// base32Decode is the reverse of base32Encode. It verifies the CRC16 checksum at the suffix. 
// The returned []byte contains both the prefix and payload, but not the CRC16 checksum.
func base32Decode(src []byte) ([]byte, error) {
	raw := make([]byte, base32Enc.DecodedLen(len(src)))
	n, err := base32Enc.Decode(raw, src)
	if err != nil {
		return nil, err
	}
	raw = raw[:n]

	if len(raw) < 4 {
		return nil, InvalidEncodingError
	}

	var crc uint16
	checksum := bytes.NewReader(raw[(len(raw) - 2):])
	if err := binary.Read(checksum, binary.LittleEndian, &crc); err != nil {
		return nil, err
	}

	// ensure checksum is valid
	if !validateCRC16(raw[0:(len(raw) - 2)], crc) {
		return nil, InvalidChecksumError
	}

	return raw[:(len(raw) - 2)], nil
}

// base32DecodeWithPrefix calls base32Decode internally, then separate the prefix from the 
// payload.
func base32DecodeWithPrefix(src []byte) (KeyPrefix, []byte, error) {
	raw, err := base32Decode(src)
	if err != nil {
		return UnknownKeyPrefix, nil, err
	}
	prefix := KeyPrefix(raw[0])
	if isUnknownKeyPrefix(prefix) {
		prefix = UnknownKeyPrefix
	}
	return prefix, raw[1:], nil
}

// base32DecodeSecret is the reverse of base32EncodeSecret.
func base32DecodeSecret(src []byte) (KeyPrefix, []byte, error) {
	raw, err := base32Decode(src)
	if err != nil {
		return SecretKeyPrefix, nil, err
	}

	// Need to do the reverse here to get back to internal representation.
	b1 := raw[0] & 248 // 248 = 11111000
	b2 := (raw[0] & 7) << 5 | ((raw[1] & 248) >> 3) // 7 = 00000111

	if KeyPrefix(b1) != SecretKeyPrefix {
		return SecretKeyPrefix, nil, InvalidKeyPrefixError
	}
	if !isPublicKeyPrefix(KeyPrefix(b2)) {
		return SecretKeyPrefix, nil, InvalidSecretError
	}
	return KeyPrefix(b2), raw[2:], nil
}