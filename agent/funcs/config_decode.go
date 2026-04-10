package funcs

import "encoding/hex"

// ResolveConfig hex-decodes and XOR-decrypts a build-time obfuscated string.
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
