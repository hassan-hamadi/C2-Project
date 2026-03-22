package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"time"
)

var (
	ServerURL       = "http://localhost:5000"
	CheckInInterval = 10 * time.Second
	AgentID         string
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

	fmt.Println("═══════════════════════════════════════")
	fmt.Println("       C2 Agent — Initialized          ")
	fmt.Println("═══════════════════════════════════════")
	fmt.Printf("  Agent ID  : %s\n", AgentID)
	fmt.Printf("  Server    : %s\n", ServerURL)
	fmt.Printf("  Interval  : %s\n", CheckInInterval)
	fmt.Printf("  OS/Arch   : %s/%s\n", runtime.GOOS, runtime.GOARCH)

	hostname, err := os.Hostname()
	if err == nil {
		fmt.Printf("  Hostname  : %s\n", hostname)
	}

	fmt.Println("═══════════════════════════════════════")
}
