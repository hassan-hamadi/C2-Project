package funcs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Encrypt encrypts plaintext with AES-256-GCM using the provided 32-byte key.
// Returns a base64-encoded string: nonce[12] + ciphertext + gcm_tag[16].
// A fresh random nonce is generated per call so identical plaintexts always
// produce different ciphertexts.
func Encrypt(key []byte, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes for GCM
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation: %w", err)
	}

	// Seal appends ciphertext+tag after the nonce so they travel together
	blob := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(blob), nil
}

// Decrypt decrypts a base64-encoded blob produced by Encrypt.
// Returns the plaintext, or an error if base64 decoding fails,
// the blob is too short, or the GCM auth tag does not match.
func Decrypt(key []byte, encoded string) ([]byte, error) {
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short (%d bytes, need > %d)", len(blob), nonceSize)
	}

	nonce, ct := blob[:nonceSize], blob[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm.Open: %w", err)
	}
	return plaintext, nil
}
