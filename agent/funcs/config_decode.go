package funcs

import "encoding/hex"

// ResolveConfig decodes a hex-encoded, multi-byte XOR-encrypted string.
// The key is cycled over the ciphertext bytes to recover the original
// plaintext. This is used at runtime to recover configuration values
// (server URL, API paths, etc.) that are masked at build time so they
// do not appear in a static strings dump of the binary.
func ResolveConfig(key []byte, hexData string) string {
	data, err := hex.DecodeString(hexData)
	if err != nil {
		return ""
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return string(out)
}
