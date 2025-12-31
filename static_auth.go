package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

/*
   ---------------------------
   Static Authenticator
   ---------------------------
*/

type StaticAuth struct {
	mu         sync.Mutex
	challenges map[string]ntlmChallengeState
}

const staticUser = "testuser"
const staticPassword = "dogood"

type authChallenge struct {
	header string
}

func (a authChallenge) Error() string {
	return "authentication challenge"
}

func (a *StaticAuth) Authenticate(
	ctx context.Context,
	r *http.Request,
) (string, error) {

	fmt.Println(r)
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		scheme, token := splitAuthHeader(authHeader)
		if scheme != "" && (strings.EqualFold(scheme, "NTLM") || strings.EqualFold(scheme, "Negotiate")) {
			canonicalScheme := canonicalAuthScheme(scheme)
			if token == "" {
				return "", authChallenge{header: canonicalScheme}
			}
			decoded, err := base64.StdEncoding.DecodeString(token)
			if err != nil {
				log.Printf("%s token decode failed from %s: %v", canonicalScheme, r.RemoteAddr, err)
				return "", authChallenge{header: canonicalScheme}
			}
			ntlmToken := decoded
			if canonicalScheme == "Negotiate" {
				ntlmToken, err = ExtractNTLMToken(decoded)
				if err != nil {
					log.Printf("Negotiate token missing NTLM for %s: %v", r.RemoteAddr, err)
					return "", authChallenge{header: canonicalScheme}
				}
			}
			msgType, err := NtlmMessageType(ntlmToken)
			if err != nil {
				log.Printf("Invalid NTLM message from %s: %v", r.RemoteAddr, err)
				return "", authChallenge{header: canonicalScheme}
			}
			switch msgType {
			case ntlmMessageTypeNegotiate:
				return "", a.ntlmChallengeError(r, canonicalScheme)
			case ntlmMessageTypeAuthenticate:
				user, err := a.verifyNTLMAuthenticate(r, ntlmToken, canonicalScheme)
				if err != nil {
					return "", err
				}
				return normalizeUser(user), nil
			default:
				return "", authChallenge{header: canonicalScheme}
			}
		}
	}
	return "", errors.New("authHeader missing or invalid")
}

func splitAuthHeader(header string) (string, string) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", ""
	}
	for i, r := range header {
		if r == ' ' || r == '\t' {
			return header[:i], strings.TrimSpace(header[i+1:])
		}
	}
	return header, ""
}

func canonicalAuthScheme(scheme string) string {
	if strings.EqualFold(scheme, "Negotiate") {
		return "Negotiate"
	}
	return "NTLM"
}

func (a *StaticAuth) ntlmChallengeError(r *http.Request, scheme string) error {
	challenge, err := a.issueNTLMChallenge(r)
	if err != nil {
		return err
	}
	if scheme == "" {
		scheme = "NTLM"
	}
	return authChallenge{header: scheme + " " + challenge}
}

func (a *StaticAuth) issueNTLMChallenge(r *http.Request) (string, error) {
	serverChallenge := make([]byte, 8)
	if _, err := rand.Read(serverChallenge); err != nil {
		return "", err
	}
	msg, err := BuildNTLMChallengeMessage(serverChallenge, ntlmTargetName)
	if err != nil {
		return "", err
	}
	key := NtlmChallengeKey(r)
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.challenges == nil {
		a.challenges = make(map[string]ntlmChallengeState)
	}
	a.pruneNTLMChallengesLocked(now)
	challengeCopy := make([]byte, len(serverChallenge))
	copy(challengeCopy, serverChallenge)
	a.challenges[key] = ntlmChallengeState{challenge: challengeCopy, issuedAt: now}

	return base64.StdEncoding.EncodeToString(msg), nil
}

func (a *StaticAuth) pruneNTLMChallengesLocked(now time.Time) {
	for key, state := range a.challenges {
		if now.Sub(state.issuedAt) > ntlmChallengeTTL {
			delete(a.challenges, key)
		}
	}
}

func (a *StaticAuth) takeNTLMChallenge(r *http.Request) ([]byte, bool) {
	key := NtlmChallengeKey(r)
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.challenges == nil {
		return nil, false
	}
	state, ok := a.challenges[key]
	if !ok {
		return nil, false
	}
	delete(a.challenges, key)
	if now.Sub(state.issuedAt) > ntlmChallengeTTL {
		return nil, false
	}
	challengeCopy := make([]byte, len(state.challenge))
	copy(challengeCopy, state.challenge)
	return challengeCopy, true
}

func (a *StaticAuth) verifyNTLMAuthenticate(r *http.Request, data []byte, scheme string) (string, error) {
	msg, err := ParseNTLMAuthenticateMessage(data)
	if err != nil {
		log.Printf("Invalid NTLM authenticate message from %s: %v", r.RemoteAddr, err)
		return "", a.ntlmChallengeError(r, scheme)
	}
	challenge, ok := a.takeNTLMChallenge(r)
	if !ok {
		log.Printf("Missing NTLM challenge for %s", NtlmChallengeKey(r))
		return "", a.ntlmChallengeError(r, scheme)
	}

	userLdap, ok := getSessionFromUserName(msg.UserName)
	if !ok {
		log.Printf("NTLM auth failed, user %q not found", msg.UserName)
		return "", a.ntlmChallengeError(r, scheme)
	}

	if !VerifyNTLMv2Response(challenge, userLdap.User.NtlmPassword, msg.NtChallengeResponse) {
		log.Printf("NTLM auth failed for user=%q domain=%q", msg.UserName, msg.DomainName)
		return "", a.ntlmChallengeError(r, scheme)
	}
	return msg.UserName, nil
}
