package protocol

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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

func TestSetSendReceiveBuffersNoop(t *testing.T) {
	gw := &Gateway{ServerConf: &ServerConf{}}
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})

	if err := gw.setSendReceiveBuffers(serverConn); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestHandleWebsocketProtocolHandshake(t *testing.T) {
	gw := &Gateway{ServerConf: &ServerConf{}}
	session := &SessionInfo{ConnId: "ws-test"}
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade websocket: %v", err)
		}
		go func() {
			gw.handleWebsocketProtocol(r.Context(), conn, session)
			close(done)
		}()
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/"
	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	t.Cleanup(func() {
		_ = clientConn.Close()
	})

	payload := []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00}
	packet := createPacket(PKT_TYPE_HANDSHAKE_REQUEST, payload)
	if err := clientConn.WriteMessage(websocket.BinaryMessage, packet); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	mt, resp, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Fatalf("expected binary message, got %d", mt)
	}

	pt, _, pkt, err := readHeader(resp)
	if err != nil {
		t.Fatalf("read response header: %v", err)
	}
	if pt != PKT_TYPE_HANDSHAKE_RESPONSE {
		t.Fatalf("expected response type %d, got %d", PKT_TYPE_HANDSHAKE_RESPONSE, pt)
	}

	r := bytes.NewReader(pkt)
	var errCode uint32
	var major, minor byte
	var serverVersion uint16
	var caps uint16
	if err := binary.Read(r, binary.LittleEndian, &errCode); err != nil {
		t.Fatalf("read error code: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &major); err != nil {
		t.Fatalf("read major: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &minor); err != nil {
		t.Fatalf("read minor: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &serverVersion); err != nil {
		t.Fatalf("read server version: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &caps); err != nil {
		t.Fatalf("read caps: %v", err)
	}
	if errCode != 0 {
		t.Fatalf("expected error code 0, got %d", errCode)
	}
	if major != payload[0] || minor != payload[1] {
		t.Fatalf("expected version %d.%d, got %d.%d", payload[0], payload[1], major, minor)
	}

	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return")
	}

	if session.TransportIn == nil || session.TransportOut == nil {
		t.Fatal("expected transports to be initialized")
	}
}
