package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetRemoteGatewayRotuerHealth(t *testing.T) {
	handler := getRemoteGatewayRotuer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if body := rec.Body.String(); body != "ok\n" {
		t.Fatalf("expected body %q, got %q", "ok\n", body)
	}
}

func TestGetRemoteGatewayRotuerRDPFile(t *testing.T) {
	handler := getRemoteGatewayRotuer()
	req := httptest.NewRequest(http.MethodGet, "http://gw.example.com:8443/rdpgw.rdp", nil)
	req.Host = "gw.example.com:8443"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/x-rdp" {
		t.Fatalf("expected content type %q, got %q", "application/x-rdp", got)
	}
	if got := rec.Header().Get("Content-Disposition"); got != `attachment; filename="`+rdpFilename+`"` {
		t.Fatalf("expected content disposition %q, got %q", `attachment; filename="`+rdpFilename+`"`, got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected cache control %q, got %q", "no-store", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "screen mode id:i:2\r\n") {
		t.Fatalf("expected fullscreen setting, got:\n%s", body)
	}
	if !strings.Contains(body, "full address:s:"+defaultRDPAddress+"\r\n") {
		t.Fatalf("expected target address, got:\n%s", body)
	}
	if !strings.Contains(body, "gatewayhostname:s:gw.example.com:8443\r\n") {
		t.Fatalf("expected gateway hostname, got:\n%s", body)
	}
}

func TestGetRemoteGatewayRotuerRoot(t *testing.T) {
	handler := getRemoteGatewayRotuer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Download a preconfigured") {
		t.Fatalf("expected index page content, got:\n%s", rec.Body.String())
	}
}

func TestGetRemoteGatewayRotuerNotFound(t *testing.T) {
	handler := getRemoteGatewayRotuer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/not-found", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
}

func TestGetRemoteGatewayRotuerGatewayRoute(t *testing.T) {
	handler := getRemoteGatewayRotuer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/remoteDesktopGateway/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
	values := rec.Header().Values("WWW-Authenticate")
	hasBasic := false
	for _, v := range values {
		if v == `Basic realm="rdpgw"` {
			hasBasic = true
		}
	}
	if !hasBasic {
		t.Fatalf("expected Basic realm challenge, got %v", values)
	}
}
