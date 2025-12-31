package ntlm

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"remotegateway/internal/session"
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
	mu             sync.Mutex
	Challenges     map[string]NtlmChallengeState
	SessionManager *session.Manager
}

const StaticUser = "testuser"
const StaticPassword = "dogood"

type AuthChallenge struct {
	Header string
}

func (a AuthChallenge) Error() string {
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
				return "", AuthChallenge{Header: canonicalScheme}
			}
			decoded, err := base64.StdEncoding.DecodeString(token)
			if err != nil {
				log.Printf("%s token decode failed from %s: %v", canonicalScheme, r.RemoteAddr, err)
				return "", AuthChallenge{Header: canonicalScheme}
			}
			ntlmToken := decoded
			if canonicalScheme == "Negotiate" {
				ntlmToken, err = extractNTLMToken(decoded)
				if err != nil {
					log.Printf("Negotiate token missing NTLM for %s: %v", r.RemoteAddr, err)
					return "", AuthChallenge{Header: canonicalScheme}
				}
			}
			msgType, err := ntlmMessageType(ntlmToken)
			if err != nil {
				log.Printf("Invalid NTLM message from %s: %v", r.RemoteAddr, err)
				return "", AuthChallenge{Header: canonicalScheme}
			}
			switch msgType {
			case ntlmMessageTypeNegotiate:
				return "", a.ntlmChallengeError(r, canonicalScheme)
			case ntlmMessageTypeAuthenticate:
				user, err := a.VerifyNTLMAuthenticate(r, ntlmToken, canonicalScheme)
				if err != nil {
					return "", err
				}
				return normalizeUser(user), nil
			default:
				return "", AuthChallenge{Header: canonicalScheme}
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
	return AuthChallenge{Header: scheme + " " + challenge}
}

func (a *StaticAuth) issueNTLMChallenge(r *http.Request) (string, error) {
	serverChallenge := make([]byte, 8)
	if _, err := rand.Read(serverChallenge); err != nil {
		return "", err
	}
	msg, err := buildNTLMChallengeMessage(serverChallenge, ntlmTargetName)
	if err != nil {
		return "", err
	}
	key := NtlmChallengeKey(r)
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.Challenges == nil {
		a.Challenges = make(map[string]NtlmChallengeState)
	}
	a.pruneNTLMChallengesLocked(now)
	challengeCopy := make([]byte, len(serverChallenge))
	copy(challengeCopy, serverChallenge)
	a.Challenges[key] = NtlmChallengeState{Challenge: challengeCopy, IssuedAt: now}

	return base64.StdEncoding.EncodeToString(msg), nil
}

func (a *StaticAuth) pruneNTLMChallengesLocked(now time.Time) {
	for key, state := range a.Challenges {
		if now.Sub(state.IssuedAt) > ntlmChallengeTTL {
			delete(a.Challenges, key)
		}
	}
}

func (a *StaticAuth) takeNTLMChallenge(r *http.Request) ([]byte, bool) {
	key := NtlmChallengeKey(r)
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.Challenges == nil {
		return nil, false
	}
	state, ok := a.Challenges[key]
	if !ok {
		return nil, false
	}
	delete(a.Challenges, key)
	if now.Sub(state.IssuedAt) > ntlmChallengeTTL {
		return nil, false
	}
	challengeCopy := make([]byte, len(state.Challenge))
	copy(challengeCopy, state.Challenge)
	return challengeCopy, true
}

func (a *StaticAuth) VerifyNTLMAuthenticate(r *http.Request, data []byte, scheme string) (string, error) {
	msg, err := parseNTLMAuthenticateMessage(data)
	if err != nil {
		log.Printf("Invalid NTLM authenticate message from %s: %v", r.RemoteAddr, err)
		return "", a.ntlmChallengeError(r, scheme)
	}
	challenge, ok := a.takeNTLMChallenge(r)
	if !ok {
		log.Printf("Missing NTLM challenge for %s", NtlmChallengeKey(r))
		return "", a.ntlmChallengeError(r, scheme)
	}

	if a.SessionManager == nil {
		log.Printf("NTLM auth failed, session manager not configured")
		return "", a.ntlmChallengeError(r, scheme)
	}

	userLdap, ok := a.SessionManager.GetSessionFromUserName(msg.UserName)
	if !ok {
		log.Printf("NTLM auth failed, user %q not found", msg.UserName)
		return "", a.ntlmChallengeError(r, scheme)
	}

	if !verifyNTLMv2Response(challenge, userLdap.User.GetNtlmPassword(), msg.NtChallengeResponse) {
		log.Printf("NTLM auth failed for user=%q domain=%q", msg.UserName, msg.DomainName)
		return "", a.ntlmChallengeError(r, scheme)
	}
	return msg.UserName, nil
}

func normalizeUser(user string) string {
	user = strings.TrimSpace(user)
	if user == "" {
		return ""
	}
	if idx := strings.LastIndex(user, "\\"); idx >= 0 {
		user = user[idx+1:]
	}
	if idx := strings.Index(user, "@"); idx > 0 {
		user = user[:idx]
	}
	return user
}
