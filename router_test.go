package main

import (
	"net/http"
	"net/http/httptest"
	"remotegateway/internal/config"
	"remotegateway/internal/session"
	"testing"
)

func TestGetRemoteGatewayRotuerHealth(t *testing.T) {
	settings := config.NewSettingType(false)
	handler := getRemoteGatewayRotuer(session.NewManager(), settings)
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
	settings := config.NewSettingType(false)
	handler := getRemoteGatewayRotuer(session.NewManager(), settings)
	req := httptest.NewRequest(http.MethodGet, "http://gw.example.com:8443/api/rdpgw.rdp", nil)
	req.Host = "gw.example.com:8443"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected status %d, got %d", http.StatusSeeOther, rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestGetRemoteGatewayRotuerRoot(t *testing.T) {
	settings := config.NewSettingType(false)
	handler := getRemoteGatewayRotuer(session.NewManager(), settings)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected status %d, got %d", http.StatusSeeOther, rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestGetRemoteGatewayRotuerNotFound(t *testing.T) {
	settings := config.NewSettingType(false)
	handler := getRemoteGatewayRotuer(session.NewManager(), settings)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/not-found", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
}

func TestGetRemoteGatewayRotuerGatewayRoute(t *testing.T) {
	settings := config.NewSettingType(false)
	handler := getRemoteGatewayRotuer(session.NewManager(), settings)
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
