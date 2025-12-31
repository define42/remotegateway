package common

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrichContextUsesXForwardedFor(t *testing.T) {
	handler := EnrichContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := GetClientIp(r.Context())
		if got != "198.51.100.10" {
			t.Fatalf("expected client ip %q, got %q", "198.51.100.10", got)
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.10, 203.0.113.1")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
}

func TestEnrichContextFallsBackToRemoteAddr(t *testing.T) {
	handler := EnrichContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := GetClientIp(r.Context())
		if got != "192.0.2.55" {
			t.Fatalf("expected client ip %q, got %q", "192.0.2.55", got)
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "192.0.2.55:8080"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
}
