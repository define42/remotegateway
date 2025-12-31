package protocol

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"remotegateway/internal/rdpgw/common"
	"strconv"
	"time"
)

type VerifyTunnelCreate func(context.Context, string) (bool, error)
type VerifyTunnelAuthFunc func(context.Context, string) (bool, error)
type VerifyServerFunc func(context.Context, string) (bool, error)
type ConvertToInternalServerFunc func(context.Context, string) (string, error)

type Server struct {
	Session                     *SessionInfo
	VerifyTunnelCreate          VerifyTunnelCreate
	VerifyTunnelAuthFunc        VerifyTunnelAuthFunc
	VerifyServerFunc            VerifyServerFunc
	ConvertToInternalServerFunc ConvertToInternalServerFunc
	RedirectFlags               int
	IdleTimeout                 int
	SmartCardAuth               bool
	TokenAuth                   bool
	ClientName                  string
	Remote                      net.Conn
	State                       int
}

type ServerConf struct {
	VerifyTunnelCreate          VerifyTunnelCreate
	VerifyTunnelAuthFunc        VerifyTunnelAuthFunc
	VerifyServerFunc            VerifyServerFunc
	ConvertToInternalServerFunc ConvertToInternalServerFunc
	RedirectFlags               RedirectFlags
	IdleTimeout                 int
	SmartCardAuth               bool
	TokenAuth                   bool
	ReceiveBuf                  int
	SendBuf                     int
}

func NewServer(s *SessionInfo, conf *ServerConf) *Server {
	h := &Server{
		State:                       SERVER_STATE_INITIAL,
		Session:                     s,
		RedirectFlags:               makeRedirectFlags(conf.RedirectFlags),
		IdleTimeout:                 conf.IdleTimeout,
		SmartCardAuth:               conf.SmartCardAuth,
		TokenAuth:                   conf.TokenAuth,
		VerifyTunnelCreate:          conf.VerifyTunnelCreate,
		VerifyServerFunc:            conf.VerifyServerFunc,
		VerifyTunnelAuthFunc:        conf.VerifyTunnelAuthFunc,
		ConvertToInternalServerFunc: conf.ConvertToInternalServerFunc,
	}
	return h
}

const tunnelId = 10

func (s *Server) Process(ctx context.Context) error {
	for {
		pt, sz, pkt, err := readMessage(s.Session.TransportIn)
		if err != nil {
			log.Printf("Server: Cannot read message from stream %s", err)
			return err
		}

		switch pt {
		case PKT_TYPE_HANDSHAKE_REQUEST:
			log.Printf("Client handshakeRequest from %s", common.GetClientIp(ctx))
			if s.State != SERVER_STATE_INITIAL {
				log.Printf("Handshake attempted while in wrong state %d != %d", s.State, SERVER_STATE_INITIAL)
				return errors.New("wrong state")
			}
			major, minor, _, _, err := s.handshakeRequest(pkt) // todo check if auth matches what the handler can do
			if err != nil {
				return fmt.Errorf("failed to parse handshake request: %w", err)
			}

			msg, err := s.handshakeResponse(major, minor)
			if err != nil {
				return err
			}

			if _, err := s.Session.TransportOut.WritePacket(msg); err != nil {
				return err
			}
			s.State = SERVER_STATE_HANDSHAKE
		case PKT_TYPE_TUNNEL_CREATE:
			log.Printf("Tunnel create")
			if s.State != SERVER_STATE_HANDSHAKE {
				log.Printf("Tunnel create attempted while in wrong state %d != %d",
					s.State, SERVER_STATE_HANDSHAKE)
				return errors.New("wrong state")
			}
			_, cookie, err := s.tunnelRequest(pkt)
			if err != nil {
				return fmt.Errorf("failed to parse tunnel request: %w", err)
			}
			if s.VerifyTunnelCreate != nil {
				if ok, _ := s.VerifyTunnelCreate(ctx, cookie); !ok {
					log.Printf("Invalid PAA cookie received from client %s", common.GetClientIp(ctx))
					return errors.New("invalid PAA cookie")
				}
			}
			msg, err := s.tunnelResponse()
			if err != nil {
				return err
			}

			if _, err := s.Session.TransportOut.WritePacket(msg); err != nil {
				return err
			}

			s.State = SERVER_STATE_TUNNEL_CREATE
		case PKT_TYPE_TUNNEL_AUTH:
			log.Printf("Tunnel auth")
			if s.State != SERVER_STATE_TUNNEL_CREATE {
				log.Printf("Tunnel auth attempted while in wrong state %d != %d",
					s.State, SERVER_STATE_TUNNEL_CREATE)
				return errors.New("wrong state")
			}
			client, err := s.tunnelAuthRequest(pkt)
			if err != nil {
				return fmt.Errorf("failed to parse tunnel auth request: %w", err)
			}

			if s.VerifyTunnelAuthFunc != nil {
				if ok, _ := s.VerifyTunnelAuthFunc(ctx, client); !ok {
					log.Printf("Invalid client name: %s", client)
					return errors.New("invalid client name")
				}
			}
			msg, err := s.tunnelAuthResponse()
			if err != nil {
				return err
			}

			if _, err := s.Session.TransportOut.WritePacket(msg); err != nil {
				return err
			}
			s.State = SERVER_STATE_TUNNEL_AUTHORIZE
		case PKT_TYPE_CHANNEL_CREATE:
			log.Printf("Channel create")
			if s.State != SERVER_STATE_TUNNEL_AUTHORIZE {
				log.Printf("Channel create attempted while in wrong state %d != %d",
					s.State, SERVER_STATE_TUNNEL_AUTHORIZE)
				return errors.New("wrong state")
			}
			server, port, err := s.channelRequest(pkt)
			if err != nil {
				return fmt.Errorf("failed to parse channel request: %w", err)
			}

			if s.ConvertToInternalServerFunc != nil {
				internalServer, err := s.ConvertToInternalServerFunc(ctx, server)
				if err != nil {
					log.Printf("Cannot convert to internal server address for %s: %s", server, err)
					return err
				}
				server = internalServer
			}

			host := net.JoinHostPort(server, strconv.Itoa(int(port)))
			if s.VerifyServerFunc != nil {
				if ok, _ := s.VerifyServerFunc(ctx, host); !ok {
					log.Printf("Not allowed to connect to %s by policy handler", host)
					return errors.New("denied by security policy")
				}
			}

			log.Printf("Establishing connection to RDP server: %s", host)
			s.Remote, err = net.DialTimeout("tcp", host, time.Second*15)
			if err != nil {
				log.Printf("Error connecting to %s, %s", host, err)
				return err
			}
			log.Printf("Connection established")
			msg, err := s.channelResponse()
			if err != nil {
				return err
			}

			if _, err := s.Session.TransportOut.WritePacket(msg); err != nil {
				return err
			}

			// Make sure to start the flow from the RDP server first otherwise connections
			// might hang eventually
			go forward(s.Remote, s.Session.TransportOut)
			s.State = SERVER_STATE_CHANNEL_CREATE
		case PKT_TYPE_DATA:
			if s.State < SERVER_STATE_CHANNEL_CREATE {
				log.Printf("Data received while in wrong state %d != %d", s.State, SERVER_STATE_CHANNEL_CREATE)
				return errors.New("wrong state")
			}
			s.State = SERVER_STATE_OPENED
			if err := receive(pkt, s.Remote); err != nil {
				return err
			}
		case PKT_TYPE_KEEPALIVE:
			// keepalives can be received while the channel is not open yet
			if s.State < SERVER_STATE_CHANNEL_CREATE {
				log.Printf("Keepalive received while in wrong state %d != %d", s.State, SERVER_STATE_CHANNEL_CREATE)
				return errors.New("wrong state")
			}

			// avoid concurrency issues
			// p.TransportIn.Write(createPacket(PKT_TYPE_KEEPALIVE, []byte{}))
		case PKT_TYPE_CLOSE_CHANNEL:
			log.Printf("Close channel")
			if s.State != SERVER_STATE_OPENED {
				log.Printf("Channel closed while in wrong state %d != %d", s.State, SERVER_STATE_OPENED)
				return errors.New("wrong state")
			}
			s.Session.TransportIn.Close()
			s.Session.TransportOut.Close()
			s.State = SERVER_STATE_CLOSED
		default:
			log.Printf("Unknown packet (size %d): %x", sz, pkt)
		}
	}
}

// Creates a packet the is a response to a handshakeRequest request
// HTTP_EXTENDED_AUTH_SSPI_NTLM is not supported in Linux
// but could be in Windows. However the NTLM protocol is insecure
func (s *Server) handshakeResponse(major byte, minor byte) ([]byte, error) {
	var caps uint16
	if s.SmartCardAuth {
		caps = caps | HTTP_EXTENDED_AUTH_SC
	}
	if s.TokenAuth {
		caps = caps | HTTP_EXTENDED_AUTH_PAA
	}

	buf := new(bytes.Buffer)

	// error_code
	if err := binary.Write(buf, binary.LittleEndian, uint32(0)); err != nil {
		return nil, err
	}

	if _, err := buf.Write([]byte{major, minor}); err != nil {
		return nil, err
	}

	// server version
	if err := binary.Write(buf, binary.LittleEndian, uint16(0)); err != nil {
		return nil, err
	}
	// extended auth capabilities
	if err := binary.Write(buf, binary.LittleEndian, uint16(caps)); err != nil {
		return nil, err
	}

	return createPacket(PKT_TYPE_HANDSHAKE_RESPONSE, buf.Bytes()), nil
}

func (s *Server) handshakeRequest(data []byte) (major byte, minor byte, version uint16, extAuth uint16, err error) {
	r := bytes.NewReader(data)

	if err = binary.Read(r, binary.LittleEndian, &major); err != nil {
		return
	}

	if err = binary.Read(r, binary.LittleEndian, &minor); err != nil {
		return
	}

	if err = binary.Read(r, binary.LittleEndian, &version); err != nil {
		return
	}

	if err = binary.Read(r, binary.LittleEndian, &extAuth); err != nil {
		return
	}

	log.Printf("major: %d, minor: %d, version: %d, ext auth: %d", major, minor, version, extAuth)
	return
}

func (s *Server) tunnelRequest(data []byte) (caps uint32, cookie string, err error) {
	var fields uint16

	r := bytes.NewReader(data)

	if err = binary.Read(r, binary.LittleEndian, &caps); err != nil {
		return
	}

	if err = binary.Read(r, binary.LittleEndian, &fields); err != nil {
		return
	}

	if _, err = r.Seek(2, io.SeekCurrent); err != nil {
		return
	}

	if fields == HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE {
		var size uint16
		if err = binary.Read(r, binary.LittleEndian, &size); err != nil {
			return
		}

		cookieB := make([]byte, size)
		if _, err = r.Read(cookieB); err != nil {
			return
		}

		cookie, err = DecodeUTF16(cookieB)
	}
	return
}

func (s *Server) tunnelResponse() ([]byte, error) {
	buf := new(bytes.Buffer)

	// server version
	if err := binary.Write(buf, binary.LittleEndian, uint16(0)); err != nil {
		return nil, err
	}

	// error code
	if err := binary.Write(buf, binary.LittleEndian, uint32(0)); err != nil {
		return nil, err
	}

	// fields present
	if err := binary.Write(buf, binary.LittleEndian, uint16(HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID|HTTP_TUNNEL_RESPONSE_FIELD_CAPS)); err != nil {
		return nil, err
	}

	// reserved
	if err := binary.Write(buf, binary.LittleEndian, uint16(0)); err != nil {
		return nil, err
	}

	// tunnel id (when is it used?)
	if err := binary.Write(buf, binary.LittleEndian, uint32(tunnelId)); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.LittleEndian, uint32(HTTP_CAPABILITY_IDLE_TIMEOUT)); err != nil {
		return nil, err
	}

	return createPacket(PKT_TYPE_TUNNEL_RESPONSE, buf.Bytes()), nil
}

func (s *Server) tunnelAuthRequest(data []byte) (string, error) {
	buf := bytes.NewReader(data)

	var size uint16
	if err := binary.Read(buf, binary.LittleEndian, &size); err != nil {
		return "", err
	}
	clData := make([]byte, size)
	if err := binary.Read(buf, binary.LittleEndian, &clData); err != nil {
		return "", err
	}

	clientName, _ := DecodeUTF16(clData)

	return clientName, nil
}

func (s *Server) tunnelAuthResponse() ([]byte, error) {
	buf := new(bytes.Buffer)

	// error code
	if err := binary.Write(buf, binary.LittleEndian, uint32(0)); err != nil {
		return nil, err
	}

	// fields present
	if err := binary.Write(buf, binary.LittleEndian, uint16(HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS|HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT)); err != nil {
		return nil, err
	}

	// reserved
	if err := binary.Write(buf, binary.LittleEndian, uint16(0)); err != nil {
		return nil, err
	}

	// idle timeout
	if s.IdleTimeout < 0 {
		s.IdleTimeout = 0
	}

	// redir flags
	if err := binary.Write(buf, binary.LittleEndian, uint32(s.RedirectFlags)); err != nil {
		return nil, err
	}

	// timeout in minutes
	if err := binary.Write(buf, binary.LittleEndian, uint32(s.IdleTimeout)); err != nil {
		return nil, err
	}

	return createPacket(PKT_TYPE_TUNNEL_AUTH_RESPONSE, buf.Bytes()), nil
}

func (s *Server) channelRequest(data []byte) (server string, port uint16, err error) {
	buf := bytes.NewReader(data)

	var resourcesSize byte
	var alternative byte
	var protocol uint16
	var nameSize uint16

	if err = binary.Read(buf, binary.LittleEndian, &resourcesSize); err != nil {
		return
	}

	if err = binary.Read(buf, binary.LittleEndian, &alternative); err != nil {
		return
	}

	if err = binary.Read(buf, binary.LittleEndian, &port); err != nil {
		return
	}

	if err = binary.Read(buf, binary.LittleEndian, &protocol); err != nil {
		return
	}

	if err = binary.Read(buf, binary.LittleEndian, &nameSize); err != nil {
		return
	}

	nameData := make([]byte, nameSize)
	if err = binary.Read(buf, binary.LittleEndian, &nameData); err != nil {
		return
	}

	server, err = DecodeUTF16(nameData)
	return
}

func (s *Server) channelResponse() ([]byte, error) {
	buf := new(bytes.Buffer)

	// error code
	if err := binary.Write(buf, binary.LittleEndian, uint32(0)); err != nil {
		return nil, err
	}

	// fields present
	if err := binary.Write(buf, binary.LittleEndian, uint16(HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID)); err != nil {
		return nil, err
	}

	// reserved
	if err := binary.Write(buf, binary.LittleEndian, uint16(0)); err != nil {
		return nil, err
	}

	// channel id is required for Windows clients
	// channel id
	if err := binary.Write(buf, binary.LittleEndian, uint32(1)); err != nil {
		return nil, err
	}

	// optional fields
	// channel id uint32 (4)
	// udp port uint16 (2)
	// udp auth cookie 1 byte for side channel
	// length uint16

	return createPacket(PKT_TYPE_CHANNEL_RESPONSE, buf.Bytes()), nil
}

func makeRedirectFlags(flags RedirectFlags) int {
	var redir = 0

	if flags.DisableAll {
		return HTTP_TUNNEL_REDIR_DISABLE_ALL
	}
	if flags.EnableAll {
		return HTTP_TUNNEL_REDIR_ENABLE_ALL
	}

	if !flags.Port {
		redir = redir | HTTP_TUNNEL_REDIR_DISABLE_PORT
	}
	if !flags.Clipboard {
		redir = redir | HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD
	}
	if !flags.Drive {
		redir = redir | HTTP_TUNNEL_REDIR_DISABLE_DRIVE
	}
	if !flags.Pnp {
		redir = redir | HTTP_TUNNEL_REDIR_DISABLE_PNP
	}
	if !flags.Printer {
		redir = redir | HTTP_TUNNEL_REDIR_DISABLE_PRINTER
	}
	return redir
}
