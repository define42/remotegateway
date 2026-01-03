package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"remotegateway/internal/rdpgw/transport"
	"syscall"
)

type RedirectFlags struct {
	Clipboard  bool
	Port       bool
	Drive      bool
	Printer    bool
	Pnp        bool
	DisableAll bool
	EnableAll  bool
}

type SessionInfo struct {
	// The connection-id (RDG-ConnID) as reported by the client
	ConnId string
	// The underlying incoming transport being either websocket or legacy http
	// in case of websocket TransportOut will equal TransportIn
	TransportIn transport.Transport
	// The underlying outgoing transport being either websocket or legacy http
	// in case of websocket TransportOut will equal TransportOut
	TransportOut transport.Transport
	// The remote desktop server (rdp, vnc etc) the clients intends to connect to
	RemoteServer string
	// The obtained client ip address
	ClientIp string
}

// readMessage parses and defragments a packet from a Transport. It returns
// at most the bytes that have been reported by the packet
func readMessage(in transport.Transport) (pt int, n int, msg []byte, err error) {
	fragment := false
	index := 0
	buf := make([]byte, 4096)

	for {
		size, pkt, err := in.ReadPacket()
		if err != nil {
			return 0, 0, []byte{0, 0}, err
		}

		// check for fragments
		var pt uint16
		var sz uint32
		var msg []byte

		if !fragment {
			pt, sz, msg, err = readHeader(pkt[:size])
			if err != nil {
				fragment = true
				index = copy(buf, pkt[:size])
				continue
			}
			index = 0
		} else {
			fragment = false
			pt, sz, msg, err = readHeader(append(buf[:index], pkt[:size]...))
			// header is corrupted even after defragmenting
			if err != nil {
				return 0, 0, []byte{0, 0}, err
			}
		}
		if !fragment {
			return int(pt), int(sz), msg, nil
		}
	}
}

// createPacket wraps the data into the protocol packet
func createPacket(pktType uint16, data []byte) (packet []byte) {
	size := len(data) + 8
	packet = make([]byte, size)
	binary.LittleEndian.PutUint16(packet[0:2], pktType)
	binary.LittleEndian.PutUint32(packet[4:8], uint32(size))
	copy(packet[8:], data)
	return packet
}

// readHeader parses a packet and verifies its reported size
func readHeader(data []byte) (packetType uint16, size uint32, packet []byte, err error) {
	// header needs to be 8 min
	if len(data) < 8 {
		return 0, 0, nil, errors.New("header too short, fragment likely")
	}
	r := bytes.NewReader(data)
	if err = binary.Read(r, binary.LittleEndian, &packetType); err != nil {
		return 0, 0, nil, err
	}

	if _, err = r.Seek(4, io.SeekStart); err != nil {
		return 0, 0, nil, err
	}

	if err = binary.Read(r, binary.LittleEndian, &size); err != nil {
		return 0, 0, nil, err
	}

	if len(data) < int(size) {
		return packetType, size, data[8:], errors.New("data incomplete, fragment received")
	}
	return packetType, size, data[8:size], nil
}

// forwards data from a Connection to Transport and wraps it in the rdpgw protocol
func forward(in net.Conn, out transport.Transport) {
	defer in.Close()

	const maxDataSize = 32 * 1024
	buf := make([]byte, maxDataSize)

	for {
		n, err := in.Read(buf)
		if err != nil {
			log.Printf("Error reading from local conn %s", err)
			break
		}
		if n == 0 {
			continue
		}
		payloadSize := 2 + n
		packetSize := 8 + payloadSize
		packet := make([]byte, packetSize)
		binary.LittleEndian.PutUint16(packet[0:2], PKT_TYPE_DATA)
		binary.LittleEndian.PutUint32(packet[4:8], uint32(packetSize))
		binary.LittleEndian.PutUint16(packet[8:10], uint16(n))
		copy(packet[10:], buf[:n])
		if _, err = out.WritePacket(packet); err != nil {
			log.Printf("Error writing to transport %s", err)
			break
		}
	}
}

// receive data received from the gateway client, unwrap and forward the remote desktop server
func receive(data []byte, out net.Conn) error {
	if len(data) < 2 {
		return io.ErrUnexpectedEOF
	}
	cblen := binary.LittleEndian.Uint16(data[:2])
	if int(cblen) > len(data)-2 {
		return io.ErrUnexpectedEOF
	}
	_, err := out.Write(data[2 : 2+int(cblen)])
	return err
}

// wrapSyscallError takes an error and a syscall name. If the error is
// a syscall.Errno, it wraps it in a os.SyscallError using the syscall name.
func wrapSyscallError(name string, err error) error {
	if _, ok := err.(syscall.Errno); ok {
		err = os.NewSyscallError(name, err)
	}
	return err
}
