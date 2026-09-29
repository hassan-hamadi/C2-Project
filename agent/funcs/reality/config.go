// Package reality implements the client-side parts of REALITY used by this
// project. The handshake implementation is adapted from xray-core; see
// THIRD_PARTY_NOTICES.md at the repository root.
//
// REALITY embeds X25519 authentication inside the TLS 1.3 ClientHello's
// SessionID field. uTLS supplies the selected ClientHello preset.
package reality

import utls "github.com/refraction-networking/utls"

// Config holds the client-side REALITY credentials injected at build time.
// This replaces xray-core's protobuf-generated Config with a plain struct
// containing only the fields the client path actually reads.
type Config struct {
	ServerName  string // SNI / decoy domain (e.g. "gateway.icloud.com")
	Fingerprint string // uTLS browser fingerprint: "chrome", "firefox", "safari"
	PublicKey   []byte // 32-byte X25519 public key from the REALITY server
	ShortId     []byte // up to 8-byte short ID matching the server's shortIds list
}

// fingerprints maps user-facing fingerprint names to uTLS ClientHelloIDs.
var fingerprints = map[string]*utls.ClientHelloID{
	"chrome":  &utls.HelloChrome_Auto,
	"firefox": &utls.HelloFirefox_Auto,
	"safari":  &utls.HelloSafari_Auto,
}

// lookupFingerprint returns the uTLS ClientHelloID for a given name.
// Returns nil if the name is unknown.
func lookupFingerprint(name string) *utls.ClientHelloID {
	if name == "" {
		return &utls.HelloChrome_Auto
	}
	return fingerprints[name]
}
