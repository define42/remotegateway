package protocol

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type hijackResponseWriter struct {
	header http.Header
	conn   net.Conn
	rw     *bufio.ReadWriter
}

func (h *hijackResponseWriter) Header() http.Header {
	if h.header == nil {
		h.header = make(http.Header)
	}
	return h.header
}

func (h *hijackResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (h *hijackResponseWriter) WriteHeader(status int) {}

func (h *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, h.rw, nil
}

func TestHandleGatewayProtocolLegacyOutAccept(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})

	rw := bufio.NewReadWriter(bufio.NewReader(serverConn), bufio.NewWriter(serverConn))
	w := &hijackResponseWriter{conn: serverConn, rw: rw}

	req := httptest.NewRequest(MethodRDGOUT, "http://example.com/remoteDesktopGateway/", nil)
	req.Header.Set(rdgConnectionIdKey, "test-conn")

	done := make(chan struct{})
	go func() {
		defer close(done)
		(&Gateway{}).HandleGatewayProtocol(w, req)
	}()

	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 256)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !bytes.HasPrefix(buf[:n], []byte("HTTP/1.1 200 OK\r\n")) {
		t.Fatalf("expected legacy accept response, got %q", buf[:n])
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return")
	}
}
