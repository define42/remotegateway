package protocol

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"reflect"
	"remotegateway/internal/rdpgw/common"
	"remotegateway/internal/rdpgw/transport"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
)

type contextKey string

const (
	rdgConnectionIdKey            = "Rdg-Connection-Id"
	MethodRDGIN                   = "RDG_IN_DATA"
	MethodRDGOUT                  = "RDG_OUT_DATA"
	sessionInfoCtxKey  contextKey = "SessionInfo"
)

var (
	connectionCache = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "rdpgw",
			Name:      "connection_cache",
			Help:      "The amount of connections in the cache",
		})

	websocketConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "rdpgw",
			Name:      "websocket_connections",
			Help:      "The count of websocket connections",
		})

	legacyConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "rdpgw",
			Name:      "legacy_connections",
			Help:      "The count of legacy https connections",
		})
)

type Gateway struct {
	ServerConf *ServerConf
}

var c = cache.New(5*time.Minute, 10*time.Minute)

func init() {
	prometheus.MustRegister(connectionCache)
	prometheus.MustRegister(legacyConnections)
	prometheus.MustRegister(websocketConnections)
}

func (g *Gateway) serverConf() *ServerConf {
	if g != nil && g.ServerConf != nil {
		return g.ServerConf
	}
	return &ServerConf{}
}

func (g *Gateway) HandleGatewayProtocol(w http.ResponseWriter, r *http.Request) {
	connectionCache.Set(float64(c.ItemCount()))

	var s *SessionInfo
	conf := g.serverConf()

	connId := r.Header.Get(rdgConnectionIdKey)
	x, found := c.Get(connId)
	if !found {
		s = &SessionInfo{ConnId: connId}
	} else {
		s = x.(*SessionInfo)
	}
	ctx := context.WithValue(r.Context(), sessionInfoCtxKey, s)

	switch r.Method {

	case MethodRDGOUT:
		if !websocket.IsWebSocketUpgrade(r) {
			g.handleLegacyProtocol(w, r.WithContext(ctx), s)
			return
		}
		r.Method = "GET" // force
		upgrader := websocket.Upgrader{
			ReadBufferSize:  conf.WebsocketReadBuffer,
			WriteBufferSize: conf.WebsocketWriteBuffer,
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Cannot upgrade falling back to old protocol: %s", err)
			return
		}
		defer conn.Close()

		err = g.setSendReceiveBuffers(conn.UnderlyingConn())
		if err != nil {
			log.Printf("Cannot set send/receive buffers: %s", err)
		}

		g.handleWebsocketProtocol(ctx, conn, s)
	case MethodRDGIN:
		g.handleLegacyProtocol(w, r.WithContext(ctx), s)
	}
}

func (g *Gateway) setSendReceiveBuffers(conn net.Conn) error {
	conf := g.serverConf()
	if conf.SendBuf < 1 && conf.ReceiveBuf < 1 {
		return nil
	}

	// conn == tls.Conn
	ptr := reflect.ValueOf(conn)
	val := reflect.Indirect(ptr)

	if val.Kind() != reflect.Struct {
		return errors.New("didn't get a struct from conn")
	}

	// this gets net.Conn -> *net.TCPConn -> net.TCPConn
	ptrConn := val.FieldByName("conn")
	valConn := reflect.Indirect(ptrConn)
	if !valConn.IsValid() {
		return errors.New("cannot find conn field")
	}
	valConn = valConn.Elem().Elem()

	// net.FD
	ptrNetFd := valConn.FieldByName("fd")
	valNetFd := reflect.Indirect(ptrNetFd)
	if !valNetFd.IsValid() {
		return errors.New("cannot find fd field")
	}

	// pfd member
	ptrPfd := valNetFd.FieldByName("pfd")
	valPfd := reflect.Indirect(ptrPfd)
	if !valPfd.IsValid() {
		return errors.New("cannot find pfd field")
	}

	// finally the exported Sysfd
	ptrSysFd := valPfd.FieldByName("Sysfd")
	if !ptrSysFd.IsValid() {
		return errors.New("cannot find Sysfd field")
	}
	fd := int(ptrSysFd.Int())

	if conf.ReceiveBuf > 0 {
		err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, conf.ReceiveBuf)
		if err != nil {
			return wrapSyscallError("setsockopt", err)
		}
	}

	if conf.SendBuf > 0 {
		err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, conf.SendBuf)
		if err != nil {
			return wrapSyscallError("setsockopt", err)
		}
	}

	return nil
}

func (g *Gateway) handleWebsocketProtocol(ctx context.Context, c *websocket.Conn, s *SessionInfo) {
	websocketConnections.Inc()
	defer websocketConnections.Dec()

	inout, _ := transport.NewWS(c)
	s.TransportOut = inout
	s.TransportIn = inout
	handler := NewServer(s, g.serverConf())
	if err := handler.Process(ctx); err != nil {
		log.Printf("Error processing handler: %s", err)
	}
}

// The legacy protocol (no websockets) uses an RDG_IN_DATA for client -> server
// and RDG_OUT_DATA for server -> client data. The handshakeRequest procedure is a bit different
// to ensure the connections do not get cached or terminated by a proxy prematurely.
func (g *Gateway) handleLegacyProtocol(w http.ResponseWriter, r *http.Request, s *SessionInfo) {
	log.Printf("Session %s, %t, %t", s.ConnId, s.TransportOut != nil, s.TransportIn != nil)

	conf := g.serverConf()
	switch r.Method {

	case MethodRDGOUT:
		out, err := transport.NewLegacy(w)
		if err != nil {
			log.Printf("cannot hijack connection to support RDG OUT data channel: %s", err)
			return
		}
		log.Printf("Opening RDGOUT for client %s", common.GetClientIp(r.Context()))

		s.TransportOut = out
		if err := out.SendAccept(true); err != nil {
			log.Printf("Error sending accept for RDG OUT data channel: %s", err)
			return
		}

		c.Set(s.ConnId, s, cache.DefaultExpiration)
	case MethodRDGIN:
		legacyConnections.Inc()
		defer legacyConnections.Dec()

		in, err := transport.NewLegacy(w)
		if err != nil {
			log.Printf("cannot hijack connection to support RDG IN data channel: %s", err)
			return
		}
		defer in.Close()

		if s.TransportIn == nil {
			s.TransportIn = in
			c.Set(s.ConnId, s, cache.DefaultExpiration)

			log.Printf("Opening RDGIN for client %s", common.GetClientIp(r.Context()))
			if err := in.SendAccept(false); err != nil {
				log.Printf("Error sending accept for RDG IN data channel: %s", err)
				return
			}

			// read some initial data
			in.Drain()

			log.Printf("Legacy handshakeRequest done for client %s", common.GetClientIp(r.Context()))
			handler := NewServer(s, conf)
			if err := handler.Process(r.Context()); err != nil {
				log.Printf("Error processing handler: %s", err)
			}
		}
	}
}
