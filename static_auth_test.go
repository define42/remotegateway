package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
	var challenge authChallenge
	if !errors.As(err, &challenge) {
		t.Fatalf("expected auth challenge error, got %T", err)
	}
	if !strings.HasPrefix(challenge.header, "NTLM ") {
		t.Fatalf("expected NTLM challenge header, got %q", challenge.header)
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
	var challenge authChallenge
	if !errors.As(err, &challenge) {
		t.Fatalf("expected auth challenge error, got %T", err)
	}
	if !strings.HasPrefix(challenge.header, "Negotiate ") {
		t.Fatalf("expected Negotiate challenge header, got %q", challenge.header)
	}
}

func TestAuthenticateNTLMAuthenticateSuccess(t *testing.T) {
	challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	req := &http.Request{Header: http.Header{}, RemoteAddr: "1.2.3.4:3389"}
	key := ntlmChallengeKey(req)
	auth := &StaticAuth{
		challenges: map[string]ntlmChallengeState{
			key: {
				challenge: challenge,
				issuedAt:  time.Now(),
			},
		},
	}

	domain := "DOMAIN"
	ntResponse := buildTestNTLMv2Response(challenge, staticUser, domain, staticPassword)
	msg := buildTestNTLMAuthenticateMessage(staticUser, domain, ntResponse, true)
	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(msg))

	user, err := auth.Authenticate(req.Context(), req)
	if err != nil {
		t.Fatalf("expected NTLM authenticate to succeed: %v", err)
	}
	if user != staticUser {
		t.Fatalf("expected user %q, got %q", staticUser, user)
	}
	if _, ok := auth.challenges[key]; ok {
		t.Fatalf("expected challenge to be consumed")
	}
}

func TestBasicAuthMiddlewareMissingCredentials(t *testing.T) {
	auth := &StaticAuth{}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	rec := httptest.NewRecorder()
	basicAuthMiddleware(auth, next).ServeHTTP(rec, req)

	if nextCalled {
		t.Fatalf("expected next handler not to be called")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
	values := rec.Header().Values("WWW-Authenticate")
	if len(values) != 1 || values[0] != `Basic realm="rdpgw"` {
		t.Fatalf("expected Basic realm challenge, got %v", values)
	}
}

func TestBasicAuthMiddlewareChallenge(t *testing.T) {
	auth := &StaticAuth{}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "NTLM")

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	rec := httptest.NewRecorder()
	basicAuthMiddleware(auth, next).ServeHTTP(rec, req)

	if nextCalled {
		t.Fatalf("expected next handler not to be called")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
	values := rec.Header().Values("WWW-Authenticate")
	if len(values) != 2 {
		t.Fatalf("expected two WWW-Authenticate headers, got %v", values)
	}
	hasNTLM := false
	hasBasic := false
	for _, v := range values {
		if v == "NTLM" {
			hasNTLM = true
		}
		if v == `Basic realm="rdpgw"` {
			hasBasic = true
		}
	}
	if !hasNTLM || !hasBasic {
		t.Fatalf("expected NTLM and Basic challenges, got %v", values)
	}
}
