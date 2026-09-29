package reality

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// VLESSRequest builds a VLESS protocol version-0 request frame that tells the
// Xray server to open a TCP stream to the given destination. The frame is
// prepended to the first write on the REALITY tunnel.
//
// Wire layout:
//
//	[version(1)] [uuid(16)] [addons_len(1)] [command(1)] [port(2)] [addr_type(1)] [addr(4)]
//
// This implementation supports one TCP stream with an IPv4 destination. It
// does not implement UDP, multiplexing, or additional VLESS commands.
func VLESSRequest(uuid []byte, destIP string, destPort uint16) ([]byte, error) {
	if len(uuid) != 16 {
		return nil, fmt.Errorf("vless: UUID must be 16 bytes, got %d", len(uuid))
	}

	ip := net.ParseIP(destIP).To4()
	if ip == nil {
		return nil, fmt.Errorf("vless: invalid IPv4 address %q", destIP)
	}

	buf := new(bytes.Buffer)
	buf.WriteByte(0x00) // VLESS version 0
	buf.Write(uuid)     // 16-byte client UUID
	buf.WriteByte(0x00) // addons length (no addons)
	buf.WriteByte(0x01) // command: TCP stream

	// Destination port (big-endian)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, destPort)
	buf.Write(portBuf)

	// Address: type 0x01 = IPv4, followed by 4 raw bytes
	buf.WriteByte(0x01)
	buf.Write(ip)

	return buf.Bytes(), nil
}
