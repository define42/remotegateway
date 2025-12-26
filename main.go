package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bolkedebruin/rdpgw/common"
	"github.com/bolkedebruin/rdpgw/protocol"
)

/*
   ---------------------------
   Static Authenticator
   ---------------------------
*/

type StaticAuth struct {
	mu         sync.Mutex
	challenges map[string]ntlmChallengeState
}

const staticUser = "hackers"
const staticPassword = "dogood"

type authChallenge struct {
	header string
}

func (a authChallenge) Error() string {
	return "authentication challenge"
}

func (a *StaticAuth) Authenticate(
	ctx context.Context,
	r *http.Request,
) (string, error) {
	fmt.Println("StaticAuth Authenticate called", r)
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		fields := strings.Fields(authHeader)
		if len(fields) > 0 && strings.EqualFold(fields[0], "NTLM") {
			if len(fields) < 2 {
				return "", a.ntlmChallengeError(r)
			}
			decoded, err := base64.StdEncoding.DecodeString(fields[1])
			if err != nil {
				log.Printf("Invalid NTLM token from %s: %v", r.RemoteAddr, err)
				return "", a.ntlmChallengeError(r)
			}
			msgType, err := ntlmMessageType(decoded)
			if err != nil {
				log.Printf("Invalid NTLM message from %s: %v", r.RemoteAddr, err)
				return "", a.ntlmChallengeError(r)
			}
			switch msgType {
			case ntlmMessageTypeNegotiate:
				return "", a.ntlmChallengeError(r)
			case ntlmMessageTypeAuthenticate:
				user, err := a.verifyNTLMAuthenticate(r, decoded)
				if err != nil {
					return "", err
				}
				return normalizeUser(user), nil
			default:
				return "", a.ntlmChallengeError(r)
			}
		}
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		return "", errors.New("missing credentials")
	}
	if username != staticUser || password != staticPassword {
		return "", errors.New("invalid username or password")
	}

	return normalizeUser(username), nil
}

/*
   ---------------------------
   Gateway auth helpers
   ---------------------------
*/

type contextKey string

const authUserKey contextKey = "authUser"

func normalizeUser(user string) string {
	user = strings.TrimSpace(user)
	if user == "" {
		return ""
	}
	if idx := strings.LastIndex(user, "\\"); idx >= 0 {
		user = user[idx+1:]
	}
	if idx := strings.Index(user, "@"); idx > 0 {
		user = user[:idx]
	}
	return user
}

func withAuthUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, authUserKey, user)
}

func authUserFromContext(ctx context.Context) (string, bool) {
	user, ok := ctx.Value(authUserKey).(string)
	if !ok || user == "" {
		return "", false
	}
	return user, true
}

func basicAuthMiddleware(authenticator *StaticAuth, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := authenticator.Authenticate(r.Context(), r)
		if err != nil {
			var challenge authChallenge
			if errors.As(err, &challenge) {
				w.Header().Add("WWW-Authenticate", challenge.header)
				w.Header().Add("WWW-Authenticate", `Basic realm="rdpgw"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			log.Printf(
				"Gateway auth failed: remote=%s client_ip=%s method=%s path=%s conn_id=%s err=%v",
				r.RemoteAddr,
				common.GetClientIp(r.Context()),
				r.Method,
				r.URL.Path,
				r.Header.Get("Rdg-Connection-Id"),
				err,
			)
			w.Header().Set("WWW-Authenticate", `Basic realm="rdpgw"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := withAuthUser(r.Context(), user)
		log.Printf(
			"Gateway connect: user=%s remote=%s client_ip=%s method=%s path=%s conn_id=%s ua=%q",
			user,
			r.RemoteAddr,
			common.GetClientIp(r.Context()),
			r.Method,
			r.URL.Path,
			r.Header.Get("Rdg-Connection-Id"),
			r.UserAgent(),
		)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("responsewriter does not support hijacking")
	}
	return h.Hijack()
}

func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *responseRecorder) Push(target string, opts *http.PushOptions) error {
	if p, ok := r.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w}

		next.ServeHTTP(rec, r)

		xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
		log.Printf(
			"request: status=%d bytes=%d dur=%s method=%s path=%s remote=%s xff=%q ua=%q conn_id=%s",
			rec.status,
			rec.bytes,
			time.Since(start).Truncate(time.Millisecond),
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
			xff,
			r.UserAgent(),
			r.Header.Get("Rdg-Connection-Id"),
		)
	})
}

func verifyTunnelAuth(ctx context.Context, client string) (bool, error) {
	user, ok := authUserFromContext(ctx)
	if !ok {
		log.Printf("missing auth user for tunnel auth")
		return false, nil
	}

	if client == "" {
		log.Printf("empty client name in tunnel auth; allowing for user=%s", user)
		return true, nil
	}

	if !strings.EqualFold(normalizeUser(client), user) {
		return false, nil
	}
	return true, nil
}

func verifyServer(ctx context.Context, host string) (bool, error) {
	user, ok := authUserFromContext(ctx)
	if !ok {
		log.Printf("missing auth user for server policy")
		return false, nil
	}

	target, err := resolveTarget(user)
	if err != nil {
		log.Printf("failed to resolve target for user %s: %v", user, err)
		return false, nil
	}

	if !strings.EqualFold(host, target) {
		return false, nil
	}
	return true, nil
}

/*
   ---------------------------
   RDP target resolver
   ---------------------------
*/

func resolveTarget(user string) (string, error) {
	switch strings.ToLower(normalizeUser(user)) {
	case "hackers":
		return "workstation:3389", nil
	case "bob":
		return "10.0.0.11:3389", nil
	default:
		return "", errors.New("no RDP target assigned")
	}
}

func ensureTLSCert(certPath, keyPath string) error {
	certInfo, certErr := os.Stat(certPath)
	keyInfo, keyErr := os.Stat(keyPath)
	if certErr == nil && keyErr == nil && certInfo.Mode().IsRegular() && keyInfo.Mode().IsRegular() {
		return nil
	}

	if (certErr == nil) != (keyErr == nil) {
		log.Printf("TLS cert/key mismatch, regenerating: cert=%v key=%v", certErr, keyErr)
	}

	dir := filepath.Dir(certPath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "rdpgw",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}

	return nil
}

/*
   ---------------------------
   Main
   ---------------------------
*/

func main() {
	certPath := "certs/server.crt"
	keyPath := "certs/server.key"

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		log.Fatalf("failed to ensure TLS certs: %v", err)
	}

	gw := protocol.Gateway{
		ServerConf: &protocol.ServerConf{
			IdleTimeout:          0,
			TokenAuth:            false,
			SmartCardAuth:        false,
			RedirectFlags:        protocol.RedirectFlags{EnableAll: true},
			VerifyTunnelAuthFunc: verifyTunnelAuth,
			VerifyServerFunc:     verifyServer,
		},
	}

	var gatewayHandler http.Handler = http.HandlerFunc(gw.HandleGatewayProtocol)
	gatewayHandler = basicAuthMiddleware(&StaticAuth{}, gatewayHandler)
	gatewayHandler = common.EnrichContext(gatewayHandler)

	mux := http.NewServeMux()

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	mux.Handle("/rdgateway/", gatewayHandler)

	mux.Handle("/remoteDesktopGateway/", gatewayHandler)
	//mux.Handle("/rpc/rpcproxy.dll", gatewayHandler)

	srv := &http.Server{
		Addr:      ":8443",
		Handler:   logRequests(mux),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},

		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),

		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  2 * time.Minute,

		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			_ = c.SetDeadline(time.Now().Add(8 * time.Hour))
			return ctx
		},
	}

	log.Println("Starting RDP Gateway with LDAP auth on :443")
	log.Fatal(srv.ListenAndServeTLS(
		certPath,
		keyPath,
	))
}
