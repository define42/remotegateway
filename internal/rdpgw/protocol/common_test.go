package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

type packetTransport struct {
	reads     [][]byte
	readIndex int
	writes    [][]byte
}

func (p *packetTransport) ReadPacket() (int, []byte, error) {
	if p.readIndex >= len(p.reads) {
		return 0, nil, io.EOF
	}
	b := p.reads[p.readIndex]
	p.readIndex++
	return len(b), b, nil
}

func (p *packetTransport) WritePacket(b []byte) (int, error) {
	cp := append([]byte{}, b...)
	p.writes = append(p.writes, cp)
	return len(b), nil
}

func (p *packetTransport) Close() error {
	return nil
}

func TestCreatePacketAndReadHeader(t *testing.T) {
	payload := []byte("abc")
	packet := createPacket(PKT_TYPE_KEEPALIVE, payload)

	pt, size, msg, err := readHeader(packet)
	if err != nil {
		t.Fatalf("readHeader failed: %v", err)
	}
	if pt != PKT_TYPE_KEEPALIVE {
		t.Fatalf("expected packet type %d, got %d", PKT_TYPE_KEEPALIVE, pt)
	}
	if int(size) != len(packet) {
		t.Fatalf("expected size %d, got %d", len(packet), size)
	}
	if !bytes.Equal(msg, payload) {
		t.Fatalf("expected payload %q, got %q", payload, msg)
	}
}

func TestReadHeaderTooShort(t *testing.T) {
	if _, _, _, err := readHeader([]byte{0x01}); err == nil {
		t.Fatal("expected error for short header")
	}
}

func TestReadMessageFragmented(t *testing.T) {
	payload := []byte("hello")
	packet := createPacket(PKT_TYPE_DATA, payload)
	first := packet[:4]
	second := packet[4:]

	in := &packetTransport{reads: [][]byte{first, second}}
	pt, size, msg, err := readMessage(in)
	if err != nil {
		t.Fatalf("readMessage failed: %v", err)
	}
	if pt != PKT_TYPE_DATA {
		t.Fatalf("expected packet type %d, got %d", PKT_TYPE_DATA, pt)
	}
	if size != len(packet) {
		t.Fatalf("expected size %d, got %d", len(packet), size)
	}
	if !bytes.Equal(msg, payload) {
		t.Fatalf("expected payload %q, got %q", payload, msg)
	}
}

func TestReadMessageComplete(t *testing.T) {
	packet := createPacket(PKT_TYPE_KEEPALIVE, nil)
	in := &packetTransport{reads: [][]byte{packet}}

	pt, size, msg, err := readMessage(in)
	if err != nil {
		t.Fatalf("readMessage failed: %v", err)
	}
	if pt != PKT_TYPE_KEEPALIVE {
		t.Fatalf("expected packet type %d, got %d", PKT_TYPE_KEEPALIVE, pt)
	}
	if size != len(packet) {
		t.Fatalf("expected size %d, got %d", len(packet), size)
	}
	if len(msg) != 0 {
		t.Fatalf("expected empty payload, got %v", msg)
	}
}

func TestReceiveWritesPayload(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})

	payload := []byte("hi")
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, uint16(len(payload))); err != nil {
		t.Fatalf("write length: %v", err)
	}
	buf.Write(payload)

	done := make(chan struct{})
	go func() {
		receive(buf.Bytes(), serverConn)
		close(done)
	}()

	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	readBuf := make([]byte, 16)
	n, err := clientConn.Read(readBuf)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if got := readBuf[:n]; !bytes.Equal(got, payload) {
		t.Fatalf("expected payload %q, got %q", payload, got)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("receive did not return")
	}
}

func TestForwardWritesPacket(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})

	out := &packetTransport{}
	done := make(chan struct{})
	go func() {
		forward(serverConn, out)
		close(done)
	}()

	payload := []byte("ping")
	if _, err := clientConn.Write(payload); err != nil {
		t.Fatalf("write to pipe: %v", err)
	}
	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("forward did not return")
	}

	if len(out.writes) == 0 {
		t.Fatal("expected forward to write a packet")
	}
	pt, _, msg, err := readHeader(out.writes[0])
	if err != nil {
		t.Fatalf("read forward packet: %v", err)
	}
	if pt != PKT_TYPE_DATA {
		t.Fatalf("expected packet type %d, got %d", PKT_TYPE_DATA, pt)
	}

	r := bytes.NewReader(msg)
	var size uint16
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		t.Fatalf("read payload length: %v", err)
	}
	got := make([]byte, size)
	if _, err := r.Read(got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("expected payload %q, got %q", payload, got)
	}
}

func TestWrapSyscallError(t *testing.T) {
	err := wrapSyscallError("setsockopt", syscall.EINVAL)
	var sysErr *os.SyscallError
	if !errors.As(err, &sysErr) {
		t.Fatalf("expected syscall error wrapper, got %T", err)
	}
	if sysErr.Syscall != "setsockopt" {
		t.Fatalf("expected syscall name %q, got %q", "setsockopt", sysErr.Syscall)
	}
}
