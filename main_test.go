package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"remotegateway/internal/config"
	"remotegateway/internal/ntlm"
	"remotegateway/internal/session"
	"remotegateway/internal/types"
	"strings"
	"testing"
	"time"
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

func seedSession(t *testing.T, sessionManager *session.Manager, username, password, domain string) {
	t.Helper()
	user, err := types.NewUser(username, password, domain)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	ctx, err := sessionManager.Load(context.Background(), "")
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if err := sessionManager.CreateSession(ctx, user); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, _, err := sessionManager.Commit(ctx); err != nil {
		t.Fatalf("commit session: %v", err)
	}
}

func defaultNTLMDomain() string {
	settings := config.NewSettingType(false)
	return settings.Get(config.NTLM_DOMAIN)
}

func TestAuthenticateNTLMAuthenticateSuccess(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	baseURL, sessionManager := setupLDAPProxyServer(t, ctx)

	loginClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	sessionCookie := loginAndGetSessionCookie(t, ctx, baseURL, loginClient, "testuser", "dogood")

	challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	req := &http.Request{Header: http.Header{}, RemoteAddr: "1.2.3.4:3389"}
	key := ntlm.NtlmChallengeKey(req)
	auth := &ntlm.StaticAuth{
		Challenges: map[string]ntlm.NtlmChallengeState{
			key: {
				Challenge: challenge,
				IssuedAt:  time.Now(),
			},
		},
		SessionManager: sessionManager,
	}

	domain := defaultNTLMDomain()
	ntResponse := ntlm.BuildTestNTLMv2Response(challenge, ntlm.StaticUser, domain, ntlm.StaticPassword)
	msg := ntlm.BuildTestNTLMAuthenticateMessage(ntlm.StaticUser, domain, ntResponse, true)
	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(msg))

	user, err := auth.Authenticate(req.Context(), req)
	if err != nil {
		t.Fatalf("expected NTLM authenticate to succeed: %v", err)
	}
	if user != ntlm.StaticUser {
		t.Fatalf("expected user %q, got %q", ntlm.StaticUser, user)
	}
	if _, ok := auth.Challenges[key]; ok {
		t.Fatalf("expected challenge to be consumed")
	}

	assertLogoutSuccess(t, ctx, baseURL, loginClient, sessionCookie)

	if _, found := sessionManager.GetSessionFromUserName("testuser"); found {
		t.Fatalf("expected session for user testuser to be destroyed")
	}
}

func TestBasicAuthMiddlewareMissingCredentials(t *testing.T) {
	auth := &ntlm.StaticAuth{}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	rec := httptest.NewRecorder()
	ntlm.BasicAuthMiddleware(auth, next).ServeHTTP(rec, req)

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
	auth := &ntlm.StaticAuth{}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "NTLM")

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	rec := httptest.NewRecorder()
	ntlm.BasicAuthMiddleware(auth, next).ServeHTTP(rec, req)

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

func TestVerifyNTLMAuthenticateSuccess(t *testing.T) {
	sessionManager := session.NewManager()
	challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	req := &http.Request{RemoteAddr: "1.2.3.4:3389", Header: http.Header{}}
	key := ntlm.NtlmChallengeKey(req)
	domain := defaultNTLMDomain()
	seedSession(t, sessionManager, ntlm.StaticUser, ntlm.StaticPassword, domain)
	auth := &ntlm.StaticAuth{
		Challenges: map[string]ntlm.NtlmChallengeState{
			key: {
				Challenge: challenge,
				IssuedAt:  time.Now(),
			},
		},
		SessionManager: sessionManager,
	}

	ntResponse := ntlm.BuildTestNTLMv2Response(challenge, ntlm.StaticUser, domain, ntlm.StaticPassword)
	msg := ntlm.BuildTestNTLMAuthenticateMessage(ntlm.StaticUser, domain, ntResponse, true)

	user, err := auth.VerifyNTLMAuthenticate(req, msg, "NTLM")
	if err != nil {
		t.Fatalf("expected NTLM auth to succeed: %v", err)
	}
	if user != ntlm.StaticUser {
		t.Fatalf("expected user %q, got %q", ntlm.StaticUser, user)
	}
}

func TestVerifyNTLMAuthenticateMissingChallenge(t *testing.T) {
	auth := &ntlm.StaticAuth{}
	req := &http.Request{RemoteAddr: "1.2.3.4:3389", Header: http.Header{}}
	domain := defaultNTLMDomain()
	ntResponse := ntlm.BuildTestNTLMv2Response([]byte{1, 2, 3, 4, 5, 6, 7, 8}, ntlm.StaticUser, domain, ntlm.StaticPassword)
	msg := ntlm.BuildTestNTLMAuthenticateMessage(ntlm.StaticUser, domain, ntResponse, true)
	user, err := auth.VerifyNTLMAuthenticate(req, msg, "NTLM")
	if err == nil {
		t.Fatalf("expected challenge error for missing NTLM challenge")
	}
	if user != "" {
		t.Fatalf("expected empty user on failure, got %q", user)
	}
	var challengeErr ntlm.AuthChallenge
	if !errors.As(err, &challengeErr) {
		t.Fatalf("expected auth challenge error, got %T", err)
	}
	if !strings.HasPrefix(challengeErr.Header, "NTLM ") {
		t.Fatalf("expected NTLM challenge header, got %q", challengeErr.Header)
	}
}

func TestVerifyNTLMAuthenticateInvalidResponse(t *testing.T) {
	sessionManager := session.NewManager()
	challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	req := &http.Request{RemoteAddr: "1.2.3.4:3389", Header: http.Header{}}
	key := ntlm.NtlmChallengeKey(req)
	domain := defaultNTLMDomain()
	seedSession(t, sessionManager, ntlm.StaticUser, ntlm.StaticPassword, domain)
	auth := &ntlm.StaticAuth{
		Challenges: map[string]ntlm.NtlmChallengeState{
			key: {
				Challenge: challenge,
				IssuedAt:  time.Now(),
			},
		},
		SessionManager: sessionManager,
	}

	ntResponse := ntlm.BuildTestNTLMv2Response(challenge, ntlm.StaticUser, domain, ntlm.StaticPassword)
	ntResponse[0] ^= 0xFF
	msg := ntlm.BuildTestNTLMAuthenticateMessage(ntlm.StaticUser, domain, ntResponse, true)

	user, err := auth.VerifyNTLMAuthenticate(req, msg, "NTLM")
	if err == nil {
		t.Fatalf("expected NTLM auth failure for invalid response")
	}
	if user != "" {
		t.Fatalf("expected empty user on failure, got %q", user)
	}
	var challengeErr ntlm.AuthChallenge
	if !errors.As(err, &challengeErr) {
		t.Fatalf("expected auth challenge error, got %T", err)
	}
}
