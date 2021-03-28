/*
Package signkey implements message signing using ed25519.

Use NewKey method to create a key, or From* methods to unmarshal from a 
previously created key.

Key unmarshaled from secret can sign and verify messages, but key unmarshaled 
from public key can only verify.

Use package signutil for a CLI utility that implements signkey.
*/
package signkey