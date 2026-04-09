package funcs

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// MakePinVerifier returns a tls.Config VerifyPeerCertificate callback that
// checks the server's leaf certificate SPKI against a pinned SHA-256 hash.
//
// The algorithm matches HPKP / RFC 7469:
//  1. Parse the leaf certificate (rawCerts[0]).
//  2. Marshal its SubjectPublicKeyInfo to DER.
//  3. SHA-256 hash the DER bytes.
//  4. Compare the hex digest to the pinned value.
//
// A mismatch tears down the TLS handshake with no fallback and no retry.
func MakePinVerifier(pinnedHash string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificates presented")
		}

		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		spkiDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to marshal public key: %w", err)
		}

		hash := sha256.Sum256(spkiDER)
		actual := hex.EncodeToString(hash[:])

		if actual != pinnedHash {
			return fmt.Errorf("certificate pin mismatch")
		}

		return nil
	}
}
