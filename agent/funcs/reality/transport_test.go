package reality

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestNewHTTPTransportIdleTimeout(t *testing.T) {
	transport := NewHTTPTransport(&TransportConfig{})
	defer transport.CloseIdleConnections()
	if transport.IdleConnTimeout != 90*time.Second {
		t.Fatalf("IdleConnTimeout = %v; want 90 seconds", transport.IdleConnTimeout)
	}
}

func TestNewHTTPTransportReusesIdleConnection(t *testing.T) {
	transport := NewHTTPTransport(&TransportConfig{})
	defer transport.CloseIdleConnections()
	dials := 0
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		dials++
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			for i := 0; i < 2; i++ {
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				request.Body.Close()
				_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}
		}()
		return client, nil
	}
	client := &http.Client{Transport: transport}
	for i := 0; i < 2; i++ {
		response, err := client.Get("http://fixture.invalid/checkin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
	}
	if dials != 1 {
		t.Fatalf("got %d dials for two requests; want one reused connection", dials)
	}
}

func TestVlessConn_ReadZeroAddons(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	vconn := &vlessConn{Conn: client}

	payload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest")

	go func() {
		// VLESS response header: version=0, addons_len=0
		server.Write([]byte{0x00, 0x00})
		server.Write(payload)
	}()

	buf := make([]byte, 1024)
	n, err := vconn.Read(buf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}

	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("expected payload %q, got %q", payload, buf[:n])
	}

	// Subsequent reads pass directly to underlying connection
	go func() {
		server.Write([]byte("more-data"))
	}()

	n2, err := vconn.Read(buf)
	if err != nil {
		t.Fatalf("unexpected second read error: %v", err)
	}
	if string(buf[:n2]) != "more-data" {
		t.Fatalf("expected 'more-data', got %q", buf[:n2])
	}
}

func TestVlessConn_ReadWithAddons(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	vconn := &vlessConn{Conn: client}
	payload := []byte("data-after-addons")

	go func() {
		// VLESS response: version=0, addons_len=4, 4 addon bytes
		server.Write([]byte{0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF})
		server.Write(payload)
	}()

	buf := make([]byte, 1024)
	n, err := vconn.Read(buf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}

	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("expected %q, got %q", payload, buf[:n])
	}
}

func TestVlessConn_TruncatedHeader(t *testing.T) {
	client, server := net.Pipe()

	vconn := &vlessConn{Conn: client}

	go func() {
		server.Write([]byte{0x00}) // only 1 byte instead of 2
		server.Close()
	}()

	buf := make([]byte, 1024)
	_, err := vconn.Read(buf)
	if err == nil {
		t.Fatal("expected error on truncated header, got nil")
	}
}

func TestVlessConn_RejectsUnsupportedVersion(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	vconn := &vlessConn{Conn: client}
	go func() {
		_, _ = server.Write([]byte{0x01, 0x00})
	}()

	buf := make([]byte, 1)
	if _, err := vconn.Read(buf); err == nil || err.Error() != "vless response version: got 1, want 0" {
		t.Fatalf("Read() error = %v, want unsupported version error", err)
	}
}

func TestVlessConn_TruncatedAddons(t *testing.T) {
	client, server := net.Pipe()

	vconn := &vlessConn{Conn: client}

	go func() {
		// claims 5 addon bytes but only sends 2 before closing
		server.Write([]byte{0x00, 0x05, 0x01, 0x02})
		server.Close()
	}()

	buf := make([]byte, 1024)
	_, err := vconn.Read(buf)
	if err == nil {
		t.Fatal("expected error on truncated addons, got nil")
	}
}

func TestVlessConn_HTTPRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	vconn := &vlessConn{Conn: client}

	go func() {
		// In real operation, Xray receives the HTTP request, forwards to backend,
		// and writes the VLESS response header when downlink data is available.
		req, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			return
		}

		body, _ := io.ReadAll(req.Body)
		req.Body.Close()

		// Write VLESS response header
		server.Write([]byte{0x00, 0x00})

		// Write HTTP response
		content := append([]byte("echo:"), body...)
		resp := &http.Response{
			StatusCode:    200,
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: int64(len(content)),
			Header:        make(http.Header),
			Body:          io.NopCloser(bytes.NewBuffer(content)),
		}
		resp.Write(server)
	}()

	tr := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return vconn, nil
		},
	}
	httpClient := &http.Client{Transport: tr}

	resp, err := httpClient.Post("http://mock-c2/api/test", "text/plain", bytes.NewBufferString("hello-world"))
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	expected := "echo:hello-world"
	if string(respBody) != expected {
		t.Fatalf("expected response %q, got %q", expected, string(respBody))
	}
}
