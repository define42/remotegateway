package main

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"strings"
	"testing"
)

func TestRDPFileContentIncludesFullscreenAndGateway(t *testing.T) {
	content := rdpFileContent("gw.example.com:8443", "workstation:3389")

	if !strings.Contains(content, "screen mode id:i:2\r\n") {
		t.Fatalf("expected fullscreen setting, got:\n%s", content)
	}
	if !strings.Contains(content, "full address:s:workstation:3389\r\n") {
		t.Fatalf("expected target address, got:\n%s", content)
	}
	if !strings.Contains(content, "gatewayhostname:s:gw.example.com:8443\r\n") {
		t.Fatalf("expected gateway hostname, got:\n%s", content)
	}
}

func TestSplitAuthHeader(t *testing.T) {
	scheme, token := splitAuthHeader("NTLM abc")
	if scheme != "NTLM" || token != "abc" {
		t.Fatalf("expected NTLM/abc, got %q/%q", scheme, token)
	}

	scheme, token = splitAuthHeader("Negotiate\t token")
	if scheme != "Negotiate" || token != "token" {
		t.Fatalf("expected Negotiate/token, got %q/%q", scheme, token)
	}

	scheme, token = splitAuthHeader("Negotiate")
	if scheme != "Negotiate" || token != "" {
		t.Fatalf("expected Negotiate with empty token, got %q/%q", scheme, token)
	}
}

func TestExtractNTLMToken(t *testing.T) {
	token := buildTestNTLMToken(ntlmMessageTypeNegotiate)
	decoded, err := extractNTLMToken(token)
	if err != nil {
		t.Fatalf("expected direct token to parse: %v", err)
	}
	if !bytes.Equal(decoded, token) {
		t.Fatalf("expected direct token to round-trip")
	}

	embedded := append([]byte{0x01, 0x02, 0x03}, token...)
	decoded, err = extractNTLMToken(embedded)
	if err != nil {
		t.Fatalf("expected embedded token to parse: %v", err)
	}
	if !bytes.Equal(decoded, token) {
		t.Fatalf("expected embedded token to match original")
	}

	if _, err := extractNTLMToken([]byte("not-ntlm")); err == nil {
		t.Fatalf("expected error for missing NTLM signature")
	}
}

func TestGatewayHostFromRequest(t *testing.T) {
	req := &http.Request{Host: "example.com:8443", Header: http.Header{}}
	if got := gatewayHostFromRequest(req); got != "example.com:8443" {
		t.Fatalf("expected host with port, got %q", got)
	}

	req = &http.Request{
		Host:   "example.com",
		Header: http.Header{"X-Forwarded-Port": []string{"8443"}},
	}
	if got := gatewayHostFromRequest(req); got != "example.com:8443" {
		t.Fatalf("expected forwarded port, got %q", got)
	}

	req = &http.Request{Header: http.Header{}}
	if got := gatewayHostFromRequest(req); got != "localhost:8443" {
		t.Fatalf("expected fallback host, got %q", got)
	}
}

func buildTestNTLMToken(messageType uint32) []byte {
	token := make([]byte, 12)
	copy(token[:8], []byte(ntlmSignature))
	binary.LittleEndian.PutUint32(token[8:12], messageType)
	return token
}
