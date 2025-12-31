package protocol

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type fakeTransport struct {
	reads     [][]byte
	readIndex int
	writes    [][]byte
	closed    bool
}

func (f *fakeTransport) ReadPacket() (int, []byte, error) {
	if f.readIndex >= len(f.reads) {
		return 0, nil, io.EOF
	}
	b := f.reads[f.readIndex]
	f.readIndex++
	return len(b), b, nil
}

func (f *fakeTransport) WritePacket(b []byte) (int, error) {
	cp := append([]byte{}, b...)
	f.writes = append(f.writes, cp)
	return len(b), nil
}

func (f *fakeTransport) Close() error {
	f.closed = true
	return nil
}

func TestServerProcessHandshakeWritesResponse(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00}
	in := &fakeTransport{reads: [][]byte{createPacket(PKT_TYPE_HANDSHAKE_REQUEST, payload)}}
	out := &fakeTransport{}
	session := &SessionInfo{TransportIn: in, TransportOut: out}
	srv := NewServer(session, &ServerConf{})

	err := srv.Process(context.Background())
	if err == nil {
		t.Fatal("expected error after input was exhausted")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
	if srv.State != SERVER_STATE_HANDSHAKE {
		t.Fatalf("expected state %d, got %d", SERVER_STATE_HANDSHAKE, srv.State)
	}
	if len(out.writes) != 1 {
		t.Fatalf("expected 1 response write, got %d", len(out.writes))
	}

	pt, _, pkt, err := readHeader(out.writes[0])
	if err != nil {
		t.Fatalf("read response header: %v", err)
	}
	if pt != PKT_TYPE_HANDSHAKE_RESPONSE {
		t.Fatalf("expected response type %d, got %d", PKT_TYPE_HANDSHAKE_RESPONSE, pt)
	}

	var errCode uint32
	var major, minor byte
	var serverVersion uint16
	var caps uint16
	r := bytes.NewReader(pkt)
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
	if major != payload[0] || minor != payload[1] {
		t.Fatalf("expected version %d.%d, got %d.%d", payload[0], payload[1], major, minor)
	}
	if errCode != 0 {
		t.Fatalf("expected error code 0, got %d", errCode)
	}
}

func TestTunnelAuthResponseClampsIdleTimeout(t *testing.T) {
	srv := &Server{RedirectFlags: 0, IdleTimeout: -5}
	packet, err := srv.tunnelAuthResponse()
	if err != nil {
		t.Fatalf("tunnelAuthResponse error: %v", err)
	}

	if srv.IdleTimeout != 0 {
		t.Fatalf("expected idle timeout to clamp to 0, got %d", srv.IdleTimeout)
	}

	pt, _, pkt, err := readHeader(packet)
	if err != nil {
		t.Fatalf("read response header: %v", err)
	}
	if pt != PKT_TYPE_TUNNEL_AUTH_RESPONSE {
		t.Fatalf("expected response type %d, got %d", PKT_TYPE_TUNNEL_AUTH_RESPONSE, pt)
	}

	r := bytes.NewReader(pkt)
	var errCode uint32
	var fields uint16
	var reserved uint16
	var redirFlags uint32
	var timeout uint32
	if err := binary.Read(r, binary.LittleEndian, &errCode); err != nil {
		t.Fatalf("read error code: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &fields); err != nil {
		t.Fatalf("read fields: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &reserved); err != nil {
		t.Fatalf("read reserved: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &redirFlags); err != nil {
		t.Fatalf("read redir flags: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &timeout); err != nil {
		t.Fatalf("read timeout: %v", err)
	}

	wantFields := uint16(HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS | HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT)
	if fields != wantFields {
		t.Fatalf("expected fields %d, got %d", wantFields, fields)
	}
	if timeout != 0 {
		t.Fatalf("expected timeout 0, got %d", timeout)
	}
	if errCode != 0 || reserved != 0 || redirFlags != 0 {
		t.Fatalf("unexpected response data err=%d reserved=%d redir=%d", errCode, reserved, redirFlags)
	}
}

func TestMakeRedirectFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags RedirectFlags
		want  int
	}{
		{
			name:  "disable-all",
			flags: RedirectFlags{DisableAll: true},
			want:  HTTP_TUNNEL_REDIR_DISABLE_ALL,
		},
		{
			name:  "enable-all",
			flags: RedirectFlags{EnableAll: true},
			want:  HTTP_TUNNEL_REDIR_ENABLE_ALL,
		},
		{
			name:  "allow-all-defaults",
			flags: RedirectFlags{Port: true, Clipboard: true, Drive: true, Printer: true, Pnp: true},
			want:  0,
		},
		{
			name:  "only-clipboard-enabled",
			flags: RedirectFlags{Clipboard: true},
			want:  HTTP_TUNNEL_REDIR_DISABLE_PORT | HTTP_TUNNEL_REDIR_DISABLE_DRIVE | HTTP_TUNNEL_REDIR_DISABLE_PNP | HTTP_TUNNEL_REDIR_DISABLE_PRINTER,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := makeRedirectFlags(tt.flags); got != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, got)
			}
		})
	}
}
