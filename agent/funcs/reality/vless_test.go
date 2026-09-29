package reality

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestVLESSRequest_Valid(t *testing.T) {
	uuid := []byte("1234567890abcdef") // 16 bytes
	destIP := "192.168.1.100"
	destPort := uint16(8443)

	frame, err := VLESSRequest(uuid, destIP, destPort)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Layout:
	// [version(1)] [uuid(16)] [addons_len(1)] [command(1)] [port(2)] [addr_type(1)] [addr(4)]
	// Total expected length = 1 + 16 + 1 + 1 + 2 + 1 + 4 = 26 bytes
	expectedLen := 26
	if len(frame) != expectedLen {
		t.Fatalf("expected length %d, got %d", expectedLen, len(frame))
	}

	if frame[0] != 0x00 {
		t.Errorf("expected version 0x00, got 0x%02x", frame[0])
	}
	if !bytes.Equal(frame[1:17], uuid) {
		t.Errorf("UUID mismatch: expected %v, got %v", uuid, frame[1:17])
	}
	if frame[17] != 0x00 {
		t.Errorf("expected addons_len 0x00, got 0x%02x", frame[17])
	}
	if frame[18] != 0x01 {
		t.Errorf("expected command 0x01 (TCP), got 0x%02x", frame[18])
	}

	port := binary.BigEndian.Uint16(frame[19:21])
	if port != destPort {
		t.Errorf("expected port %d, got %d", destPort, port)
	}

	if frame[21] != 0x01 {
		t.Errorf("expected addr_type 0x01 (IPv4), got 0x%02x", frame[21])
	}

	expectedIP := net.ParseIP(destIP).To4()
	if !bytes.Equal(frame[22:26], expectedIP) {
		t.Errorf("IP mismatch: expected %v, got %v", expectedIP, frame[22:26])
	}
}

func TestVLESSRequest_InvalidUUID(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		[]byte("short"),
		[]byte("12345678901234567"), // 17 bytes
	}
	for _, c := range cases {
		_, err := VLESSRequest(c, "127.0.0.1", 5000)
		if err == nil {
			t.Errorf("expected error for UUID length %d, got nil", len(c))
		}
	}
}

func TestVLESSRequest_InvalidIP(t *testing.T) {
	uuid := make([]byte, 16)
	cases := []string{
		"",
		"not-an-ip",
		"999.999.999.999",
		"2001:db8::1", // IPv6 not supported by vless version 0 IPv4 parser
	}
	for _, ip := range cases {
		_, err := VLESSRequest(uuid, ip, 5000)
		if err == nil {
			t.Errorf("expected error for invalid IP %q, got nil", ip)
		}
	}
}
