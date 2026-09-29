// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// you can obtain one at https://mozilla.org/MPL/2.0/.
//
// Adapted from xray-core/transport/internet/reality/reality.go:
// https://github.com/XTLS/Xray-core/blob/main/transport/internet/reality/reality.go
// Modified for this project in 2026.
package reality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

// Protocol version embedded in SessionID[0:3].
// These must match the Xray server's expected client version range.
const (
	versionX byte = 26
	versionY byte = 3
	versionZ byte = 27
)

// UConn wraps a uTLS connection with REALITY authentication state.
type UConn struct {
	*utls.UConn
	Config     *Config
	ServerName string
	AuthKey    []byte
	Verified   bool
}

// VerifyPeerCertificate is the TLS verification callback. When the server
// returns a REALITY-forged certificate (ed25519 pubkey + HMAC-SHA512 signature
// derived from AuthKey), it sets Verified=true. Otherwise it falls through to
// standard X.509 verification against the decoy domain. This means the server
// bounced us to the real site (auth failure or active probe).
func (c *UConn) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("reality: no peer certificates presented")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("reality: invalid peer certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return c.verifyParsedPeerCertificates(certs)
}

func (c *UConn) verifyParsedPeerCertificates(certs []*x509.Certificate) error {
	if c == nil || len(certs) == 0 || certs[0] == nil {
		return fmt.Errorf("reality: no peer certificates presented")
	}
	c.Verified = false

	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			// Server returned a REALITY-forged cert. Auth succeeded.
			c.Verified = true
			return nil
		}
	}

	// Verify a non-REALITY certificate against the configured decoy name.
	// This path runs when the server rejected our credentials and spliced us
	// to the real decoy site, or when an active probe is connecting.
	opts := x509.VerifyOptions{
		DNSName:       c.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		if cert == nil {
			return fmt.Errorf("reality: invalid peer certificate chain")
		}
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

// newAesGcm creates an AES-GCM AEAD from a raw key.
// Inlined replacement for xray-core/common/crypto.NewAesGcm.
func newAesGcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Dial establishes a REALITY-authenticated TLS connection over an existing
// TCP connection. It adapts xray-core's client path without its framework,
// spider fallback, or ML-DSA verification.
//
// On success, the returned net.Conn is a fully authenticated REALITY tunnel
// with the selected uTLS ClientHello preset. On failure (including auth
// rejection by the server), it returns an error.
func Dial(c net.Conn, config *Config, ctx context.Context) (*UConn, error) {
	uConn := &UConn{
		Config: config,
	}

	utlsConfig := &utls.Config{
		VerifyPeerCertificate:  uConn.VerifyPeerCertificate,
		ServerName:             config.ServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}
	uConn.ServerName = utlsConfig.ServerName

	fingerprint := lookupFingerprint(config.Fingerprint)
	if fingerprint == nil {
		return nil, fmt.Errorf("reality: unknown fingerprint %q", config.Fingerprint)
	}

	uConn.UConn = utls.UClient(c, utlsConfig, *fingerprint)

	// REALITY places its authentication blob in the ClientHello SessionID.
	{
		uConn.BuildHandshakeState()
		hello := uConn.HandshakeState.Hello

		hello.SessionId = make([]byte, 32)
		copy(hello.Raw[39:], hello.SessionId)

		// Layout: version(3), reserved(1), timestamp(4), short ID(8), GCM tag(16).
		hello.SessionId[0] = versionX
		hello.SessionId[1] = versionY
		hello.SessionId[2] = versionZ
		hello.SessionId[3] = 0 // reserved
		binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
		copy(hello.SessionId[8:], config.ShortId)

		// Derive the shared secret from uTLS's ephemeral key and the REALITY key.
		publicKey, err := ecdh.X25519().NewPublicKey(config.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("reality: invalid public key: %w", err)
		}

		// uTLS stores the client's ephemeral ECDHE private key here.
		// Try the standard field first, then the ML-KEM+ECDHE hybrid field
		// (used by newer Chrome fingerprints with X25519MLKEM768).
		ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
		if ecdhe == nil {
			ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
		}
		if ecdhe == nil {
			return nil, fmt.Errorf("reality: fingerprint %q does not support TLS 1.3 key shares", config.Fingerprint)
		}

		uConn.AuthKey, _ = ecdhe.ECDH(publicKey)
		if uConn.AuthKey == nil {
			return nil, fmt.Errorf("reality: X25519 ECDH failed (shared key is nil)")
		}

		// Derive AuthKey in place, matching xray-core's client path.
		if _, err := hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20], []byte("REALITY")).Read(uConn.AuthKey); err != nil {
			return nil, fmt.Errorf("reality: HKDF: %w", err)
		}

		// Encrypt the first half in place; the second half receives the GCM tag.
		aead, err := newAesGcm(uConn.AuthKey)
		if err != nil {
			return nil, fmt.Errorf("reality: AES-GCM init: %w", err)
		}

		aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)
	}

	// uTLS handles the TLS flow after REALITY modifies the SessionID.
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	// If the server didn't authenticate us (Verified is false), we got the
	// real decoy site's certificate. This means the server rejected our
	// credentials and transparently proxied us to the genuine site.
	//
	// xray-core can browse the decoy on this path. This focused client fails
	// the connection so the caller can retry.
	if !uConn.Verified {
		return nil, fmt.Errorf("reality: server rejected credentials (received real certificate)")
	}

	return uConn, nil
}
