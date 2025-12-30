package main

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

type trackingWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (t *trackingWriter) Header() http.Header {
	if t.header == nil {
		t.header = make(http.Header)
	}
	return t.header
}

func (t *trackingWriter) Write(b []byte) (int, error) {
	return t.body.Write(b)
}

func (t *trackingWriter) WriteHeader(status int) {
	t.status = status
}

type flushWriter struct {
	trackingWriter
	flushed bool
}

func (f *flushWriter) Flush() {
	f.flushed = true
}

type pushWriter struct {
	trackingWriter
	target string
	opts   *http.PushOptions
}

func (p *pushWriter) Push(target string, opts *http.PushOptions) error {
	p.target = target
	p.opts = opts
	return nil
}

type hijackWriter struct {
	trackingWriter
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (h *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, h.rw, nil
}

/*
	func TestVerifyTunnelAuth(t *testing.T) {
		ctxUser := withAuthUser(context.Background(), "ubuntu")
		tests := []struct {
			name   string
			ctx    context.Context
			client string
			want   bool
		}{
			{name: "missing-user", ctx: context.Background(), client: "client", want: false},
			{name: "empty-client", ctx: ctxUser, client: "", want: true},
			{name: "normalized-match", ctx: ctxUser, client: "DOMAIN\\UBUNTU", want: true},
			{name: "mismatch", ctx: ctxUser, client: "bob", want: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := verifyTunnelAuth(tt.ctx, tt.client)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Fatalf("expected %v, got %v", tt.want, got)
				}
			})
		}
	}
*/
/*
func TestVerifyServer(t *testing.T) {
	ctxUbuntu := withAuthUser(context.Background(), "ubuntu")
	ctxBob := withAuthUser(context.Background(), "bob")
	ctxUnknown := withAuthUser(context.Background(), "alice")
	tests := []struct {
		name string
		ctx  context.Context
		host string
		want bool
	}{
		{name: "missing-user", ctx: context.Background(), host: "workstation:3389", want: false},
		{name: "unknown-user", ctx: ctxUnknown, host: "workstation:3389", want: false},
		{name: "match-ubuntu", ctx: ctxUbuntu, host: "workstation:3389", want: true},
		{name: "match-ubuntu-case", ctx: ctxUbuntu, host: "WORKSTATION:3389", want: true},
		{name: "mismatch-ubuntu", ctx: ctxUbuntu, host: "workstation:3390", want: false},
		{name: "match-bob", ctx: ctxBob, host: "10.0.0.11:3389", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verifyServer(tt.ctx, tt.host)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
*/
func TestEnsureTLSCertCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "certs", "server.crt")
	keyPath := filepath.Join(dir, "certs", "server.key")

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		t.Fatalf("expected certs to be created: %v", err)
	}

	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("expected cert file: %v", err)
	}
	if !certInfo.Mode().IsRegular() || certInfo.Size() == 0 {
		t.Fatalf("expected cert file to be regular and non-empty")
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("expected key file: %v", err)
	}
	if !keyInfo.Mode().IsRegular() || keyInfo.Size() == 0 {
		t.Fatalf("expected key file to be regular and non-empty")
	}

	certBefore, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("expected to read cert file: %v", err)
	}
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("expected to read key file: %v", err)
	}

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		t.Fatalf("expected second ensure to succeed: %v", err)
	}

	certAfter, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("expected to read cert file: %v", err)
	}
	keyAfter, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("expected to read key file: %v", err)
	}
	if !bytes.Equal(certBefore, certAfter) || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatalf("expected cert and key files to remain unchanged")
	}
}

func TestEnsureTLSCertRegeneratesOnMismatch(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, []byte("dummy"), 0600); err != nil {
		t.Fatalf("expected to write dummy cert: %v", err)
	}
	before, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("expected to read dummy cert: %v", err)
	}

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		t.Fatalf("expected regenerate to succeed: %v", err)
	}

	after, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("expected to read cert: %v", err)
	}
	if bytes.Equal(before, after) {
		t.Fatalf("expected cert file to be regenerated")
	}
	if info, err := os.Stat(keyPath); err != nil || info.Size() == 0 {
		t.Fatalf("expected key file to be created")
	}
}

func TestResponseRecorderWriteAndHeader(t *testing.T) {
	tw := &trackingWriter{}
	rec := &responseRecorder{ResponseWriter: tw}

	rec.WriteHeader(http.StatusAccepted)
	if rec.status != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, rec.status)
	}
	if tw.status != http.StatusAccepted {
		t.Fatalf("expected writer status %d, got %d", http.StatusAccepted, tw.status)
	}

	n, err := rec.Write([]byte("ok"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected to write 2 bytes, wrote %d", n)
	}
	if rec.bytes != 2 {
		t.Fatalf("expected bytes 2, got %d", rec.bytes)
	}
	if got := tw.body.String(); got != "ok" {
		t.Fatalf("expected body %q, got %q", "ok", got)
	}
}

func TestResponseRecorderWriteDefaultsStatus(t *testing.T) {
	tw := &trackingWriter{}
	rec := &responseRecorder{ResponseWriter: tw}

	if _, err := rec.Write([]byte("hi")); err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if rec.status != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.status)
	}
	if rec.bytes != 2 {
		t.Fatalf("expected bytes 2, got %d", rec.bytes)
	}
}

func TestResponseRecorderFlushPushHijack(t *testing.T) {
	fw := &flushWriter{}
	rec := &responseRecorder{ResponseWriter: fw}
	rec.Flush()
	if !fw.flushed {
		t.Fatalf("expected flush to be forwarded")
	}

	pw := &pushWriter{}
	rec = &responseRecorder{ResponseWriter: pw}
	opts := &http.PushOptions{Method: http.MethodGet}
	if err := rec.Push("/ok", opts); err != nil {
		t.Fatalf("expected push to succeed: %v", err)
	}
	if pw.target != "/ok" || pw.opts != opts {
		t.Fatalf("expected push args to be forwarded")
	}

	rec = &responseRecorder{ResponseWriter: &trackingWriter{}}
	if err := rec.Push("/nope", nil); err != http.ErrNotSupported {
		t.Fatalf("expected push to be unsupported")
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1))
	hw := &hijackWriter{conn: c1, rw: rw}
	rec = &responseRecorder{ResponseWriter: hw}
	conn, gotRW, err := rec.Hijack()
	if err != nil {
		t.Fatalf("expected hijack to succeed: %v", err)
	}
	if conn != c1 || gotRW != rw {
		t.Fatalf("expected hijack to return provided values")
	}

	rec = &responseRecorder{ResponseWriter: &trackingWriter{}}
	if _, _, err := rec.Hijack(); err == nil {
		t.Fatalf("expected hijack to fail for unsupported writer")
	}
}
