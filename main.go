package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"time"

	"remotegateway/internal/rdpgw/common"
	"remotegateway/internal/rdpgw/protocol"
	"remotegateway/internal/virt"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
)

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

		fmt.Println("Basic auth middleware called")
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

// getIPOfVm allows tests to stub VM lookups.
var getIPOfVm = virt.GetIpOfVm

func converToInternServer(ctx context.Context, host string) (string, error) {

	user, ok := authUserFromContext(ctx)
	if !ok {
		log.Printf("missing auth user for server policy")
		return "", fmt.Errorf("missing auth user")
	}

	if host == "" || user == "" {
		log.Printf("empty host or user in server policy: host=%q user=%q", host, user)
		return "", fmt.Errorf("empty host or user")
	}

	if strings.HasPrefix(host, user) {
		return getIPOfVm(host)
	}

	return "", fmt.Errorf("denying server for user=%s host=%s", user, host)
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

func gatewayRouter() http.Handler {
	gw := protocol.Gateway{
		ServerConf: &protocol.ServerConf{
			IdleTimeout:                 0,
			TokenAuth:                   false,
			SmartCardAuth:               false,
			RedirectFlags:               protocol.RedirectFlags{EnableAll: true},
			ConvertToInternalServerFunc: converToInternServer,
		},
	}

	var gatewayHandler http.Handler = http.HandlerFunc(gw.HandleGatewayProtocol)
	gatewayHandler = basicAuthMiddleware(&StaticAuth{}, gatewayHandler)
	gatewayHandler = common.EnrichContext(gatewayHandler)
	return gatewayHandler
}

func getRemoteGatewayRotuer() http.Handler {

	router := chi.NewRouter()
	router.Use(sessionManager.LoadAndSave)

	router.Post("/login", handleLoginPost)
	router.Get("/login", handleLoginGet)
	router.HandleFunc("/logout", handleLogout)

	router.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok\n")); err != nil {
			log.Printf("failed to write health response: %v", err)
		}
	})

	apiCfg := huma.DefaultConfig("ContainerVault", "1.0.0")
	apiCfg.OpenAPIPath = ""
	apiCfg.DocsPath = ""
	apiCfg.SchemasPath = ""
	api := humachi.New(router, apiCfg)
	registerAPI(api)

	//mux.Handle("/rdgateway/", gatewayHandler)
	gatewayHandler := gatewayRouter()

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	//mux.Handle("/rpc/rpcproxy.dll", gatewayHandler)
	return logRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/remoteDesktopGateway" || strings.HasPrefix(path, "/remoteDesktopGateway/") {
			// Bypass chi so custom RDG_* methods reach the gateway handler.
			gatewayHandler.ServeHTTP(w, r)
			return
		}
		router.ServeHTTP(w, r)
	}))

}

func registerAPI(api huma.API) {
	group := huma.NewGroup(api, "/api")
	group.UseMiddleware(sessionMiddleware(api))
	huma.Get(group, "/rdpgw.rdp", func(_ context.Context, _ *struct{}) (*huma.StreamResponse, error) {
		return &huma.StreamResponse{
			Body: func(ctx huma.Context) {
				req, w := humachi.Unwrap(ctx)
				gatewayHost := gatewayHostFromRequest(req)
				targetHost := rdpTargetFromRequest(req)
				rdpContent := rdpFileContent(gatewayHost, targetHost)

				w.Header().Set("Content-Type", "application/x-rdp")
				w.Header().Set("Content-Disposition", `attachment; filename="`+rdpFilename+`"`)
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusOK)
				if _, err := w.Write([]byte(rdpContent)); err != nil {
					log.Printf("failed to write RDP file response: %v", err)
				}
			},
		}, nil
	}, func(op *huma.Operation) {
		op.Hidden = true
	})

	huma.Get(group, "/dashboard", func(_ context.Context, _ *struct{}) (*huma.StreamResponse, error) {
		return &huma.StreamResponse{
			Body: func(ctx huma.Context) {
				req, w := humachi.Unwrap(ctx)
				gatewayHost := gatewayHostFromRequest(req)
				targetHost := rdpTargetFromRequest(req)
				renderIndexPage(w, gatewayHost, targetHost)
			},
		}, nil
	}, func(op *huma.Operation) {
		op.Hidden = true
	})
}

func main() {

	//	fmt.Println(virt.ListVMs())

	mux := getRemoteGatewayRotuer()

	srv := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
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

	certPath := "certs/server.crt"
	keyPath := "certs/server.key"

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		log.Fatalf("failed to ensure TLS certs: %v", err)
	}

	log.Println("Starting RDP Gateway with LDAP auth on :443")
	log.Fatal(srv.ListenAndServeTLS(certPath, keyPath))
}
