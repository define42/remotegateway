package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAuthenticateBasicSuccess(t *testing.T) {
	auth := &StaticAuth{}
	req := &http.Request{Header: http.Header{}, RemoteAddr: "1.2.3.4:3389"}
	req.SetBasicAuth(staticUser, staticPassword)

	user, err := auth.Authenticate(req.Context(), req)
	if err != nil {
		t.Fatalf("expected basic auth to succeed: %v", err)
	}
	if user != staticUser {
		t.Fatalf("expected user %q, got %q", staticUser, user)
	}
}

func TestAuthenticateBasicMissing(t *testing.T) {
	auth := &StaticAuth{}
	req := &http.Request{Header: http.Header{}, RemoteAddr: "1.2.3.4:3389"}

	user, err := auth.Authenticate(req.Context(), req)
	if err == nil {
		t.Fatalf("expected error for missing credentials")
	}
	if user != "" {
		t.Fatalf("expected empty user on error, got %q", user)
	}
	if err.Error() != "missing credentials" {
		t.Fatalf("expected missing credentials error, got %q", err.Error())
	}
}

func TestAuthenticateBasicInvalid(t *testing.T) {
	auth := &StaticAuth{}
	req := &http.Request{Header: http.Header{}, RemoteAddr: "1.2.3.4:3389"}
	req.SetBasicAuth(staticUser, "wrong")

	user, err := auth.Authenticate(req.Context(), req)
	if err == nil {
		t.Fatalf("expected error for invalid credentials")
	}
	if user != "" {
		t.Fatalf("expected empty user on error, got %q", user)
	}
	if err.Error() != "invalid username or password" {
		t.Fatalf("expected invalid credentials error, got %q", err.Error())
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
