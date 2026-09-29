package reality

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

func TestLookupFingerprint(t *testing.T) {
	cases := []struct {
		name     string
		expected *utls.ClientHelloID
	}{
		{"chrome", &utls.HelloChrome_Auto},
		{"firefox", &utls.HelloFirefox_Auto},
		{"safari", &utls.HelloSafari_Auto},
		{"", &utls.HelloChrome_Auto}, // default fallback
		{"nonexistent", nil},
	}

	for _, tc := range cases {
		got := lookupFingerprint(tc.name)
		if got != tc.expected {
			t.Errorf("lookupFingerprint(%q) = %v, want %v", tc.name, got, tc.expected)
		}
	}
}

func TestNewAesGcm(t *testing.T) {
	// Valid 16-byte key (AES-128)
	k16 := make([]byte, 16)
	aead16, err := newAesGcm(k16)
	if err != nil {
		t.Fatalf("unexpected error for 16-byte key: %v", err)
	}
	if aead16.NonceSize() != 12 || aead16.Overhead() != 16 {
		t.Errorf("unexpected AEAD parameters for 16-byte key")
	}

	// Valid 32-byte key (AES-256)
	k32 := make([]byte, 32)
	aead32, err := newAesGcm(k32)
	if err != nil {
		t.Fatalf("unexpected error for 32-byte key: %v", err)
	}
	if aead32.NonceSize() != 12 || aead32.Overhead() != 16 {
		t.Errorf("unexpected AEAD parameters for 32-byte key")
	}

	// Invalid key size (10 bytes)
	kInvalid := make([]byte, 10)
	_, err = newAesGcm(kInvalid)
	if err == nil {
		t.Errorf("expected error for 10-byte key, got nil")
	}
}

func TestVerifyPeerCertificate_ForgedRealityCert(t *testing.T) {
	// Generate an Ed25519 key pair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	authKey := make([]byte, 32)
	if _, err := rand.Read(authKey); err != nil {
		t.Fatalf("rand failed: %v", err)
	}

	// Create forged REALITY signature: HMAC-SHA512(authKey, pub)
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	validSig := h.Sum(nil)

	// Create mock certificate
	cert := &x509.Certificate{
		PublicKey: pub,
		Signature: validSig,
	}

	uConn := &UConn{
		AuthKey:    authKey,
		ServerName: "gateway.icloud.com",
	}

	// Verification with valid signature should succeed and set Verified = true
	err = uConn.verifyParsedPeerCertificates([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("VerifyPeerCertificate failed: %v", err)
	}
	if !uConn.Verified {
		t.Errorf("expected uConn.Verified to be true, got false")
	}

	// Verification with invalid signature should fail
	cert.Signature = []byte("invalid-sig")
	err = uConn.verifyParsedPeerCertificates([]*x509.Certificate{cert})
	if err == nil {
		t.Errorf("expected error on invalid signature, got nil")
	}
	if uConn.Verified {
		t.Errorf("expected uConn.Verified to be false on invalid signature")
	}
}

func TestVerifyPeerCertificate_RejectsMissingOrMalformedChain(t *testing.T) {
	uConn := &UConn{ServerName: "example.invalid"}
	for _, chain := range [][][]byte{nil, {[]byte("not a certificate")}} {
		if err := uConn.VerifyPeerCertificate(chain, nil); err == nil {
			t.Fatalf("expected invalid certificate chain to be rejected")
		}
	}
	if err := uConn.verifyParsedPeerCertificates([]*x509.Certificate{nil}); err == nil {
		t.Fatal("expected nil parsed certificate to be rejected")
	}
}

func TestDial_InvalidConfig(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// 1. Unknown fingerprint
	cfg1 := &Config{
		ServerName:  "gateway.icloud.com",
		Fingerprint: "unknown-browser",
		PublicKey:   make([]byte, 32),
	}
	_, err := Dial(client, cfg1, ctx)
	if err == nil {
		t.Errorf("expected error for unknown fingerprint, got nil")
	}

	// 2. Invalid public key length
	cfg2 := &Config{
		ServerName:  "gateway.icloud.com",
		Fingerprint: "chrome",
		PublicKey:   []byte("too-short"),
	}
	_, err = Dial(client, cfg2, ctx)
	if err == nil {
		t.Errorf("expected error for invalid public key, got nil")
	}
}

func TestSessionIDLayoutAndRoundtrip(t *testing.T) {
	// Generate server REALITY key pair (X25519)
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	serverPub := serverPriv.PublicKey().Bytes()

	// Client ephemeral key pair (X25519)
	clientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	// Emulate client-side AuthKey derivation
	clientShared, err := clientPriv.ECDH(serverPriv.PublicKey())
	if err != nil {
		t.Fatalf("client ECDH failed: %v", err)
	}

	random := make([]byte, 32)
	rand.Read(random)

	clientAuthKey := make([]byte, 32)
	copy(clientAuthKey, clientShared)
	if _, err := hkdf.New(sha256.New, clientAuthKey, random[:20], []byte("REALITY")).Read(clientAuthKey); err != nil {
		t.Fatalf("HKDF failed: %v", err)
	}

	// Emulate SessionID layout
	sessionId := make([]byte, 32)
	shortId := []byte("shortid8")
	sessionId[0] = versionX
	sessionId[1] = versionY
	sessionId[2] = versionZ
	sessionId[3] = 0
	binary.BigEndian.PutUint32(sessionId[4:], uint32(time.Now().Unix()))
	copy(sessionId[8:], shortId)

	// Encrypt SessionID[:16] in place using AES-GCM
	aead, err := newAesGcm(clientAuthKey)
	if err != nil {
		t.Fatalf("AES-GCM failed: %v", err)
	}

	rawHello := make([]byte, 200)
	copy(rawHello[39:], sessionId)
	aead.Seal(sessionId[:0], random[20:], sessionId[:16], rawHello)

	// Now emulate server-side verification:
	// Server derives same shared secret using serverPriv and clientPriv.PublicKey()
	serverShared, err := serverPriv.ECDH(clientPriv.PublicKey())
	if err != nil {
		t.Fatalf("server ECDH failed: %v", err)
	}

	serverAuthKey := make([]byte, 32)
	copy(serverAuthKey, serverShared)
	if _, err := hkdf.New(sha256.New, serverAuthKey, random[:20], []byte("REALITY")).Read(serverAuthKey); err != nil {
		t.Fatalf("server HKDF failed: %v", err)
	}

	if !bytes.Equal(clientAuthKey, serverAuthKey) {
		t.Fatalf("auth key mismatch between client and server")
	}

	serverAead, err := newAesGcm(serverAuthKey)
	if err != nil {
		t.Fatalf("server AEAD failed: %v", err)
	}

	decryptedSessionId, err := serverAead.Open(nil, random[20:], sessionId, rawHello)
	if err != nil {
		t.Fatalf("server AES-GCM decryption failed: %v", err)
	}

	// Verify decrypted layout
	if decryptedSessionId[0] != versionX || decryptedSessionId[1] != versionY || decryptedSessionId[2] != versionZ {
		t.Errorf("version mismatch in decrypted SessionID")
	}
	if !bytes.Equal(decryptedSessionId[8:16], shortId) {
		t.Errorf("shortId mismatch in decrypted SessionID: got %q, want %q", decryptedSessionId[8:16], shortId)
	}
	_ = serverPub
}
