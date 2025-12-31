package ntlm

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
)

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

func TestAuthenticateNTLMNegotiateChallenge(t *testing.T) {
	auth := &StaticAuth{}
	req := &http.Request{Header: http.Header{}, RemoteAddr: "1.2.3.4:3389"}
	token := buildTestNTLMToken(ntlmMessageTypeNegotiate)
	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(token))

	user, err := auth.Authenticate(req.Context(), req)
	if err == nil {
		t.Fatalf("expected NTLM challenge error")
	}
	if user != "" {
		t.Fatalf("expected empty user on challenge, got %q", user)
	}
	var challenge AuthChallenge
	if !errors.As(err, &challenge) {
		t.Fatalf("expected auth challenge error, got %T", err)
	}
	if !strings.HasPrefix(challenge.Header, "NTLM ") {
		t.Fatalf("expected NTLM challenge header, got %q", challenge.Header)
	}
}

func TestAuthenticateNegotiateChallenge(t *testing.T) {
	auth := &StaticAuth{}
	req := &http.Request{Header: http.Header{}, RemoteAddr: "1.2.3.4:3389"}
	token := buildTestNTLMToken(ntlmMessageTypeNegotiate)
	req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(token))

	user, err := auth.Authenticate(req.Context(), req)
	if err == nil {
		t.Fatalf("expected Negotiate challenge error")
	}
	if user != "" {
		t.Fatalf("expected empty user on challenge, got %q", user)
	}
	var challenge AuthChallenge
	if !errors.As(err, &challenge) {
		t.Fatalf("expected auth challenge error, got %T", err)
	}
	if !strings.HasPrefix(challenge.Header, "Negotiate ") {
		t.Fatalf("expected Negotiate challenge header, got %q", challenge.Header)
	}
}
