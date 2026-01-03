package ntlm

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"remotegateway/internal/rdpgw/protocol"
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
	rdgUserID := strings.TrimSpace(r.Header.Get("Rdg-User-Id"))
	if rdgUserID != "" {
		decoded, err := base64.StdEncoding.DecodeString(rdgUserID)
		if err != nil {
			log.Printf("Rdg-User-Id base64 decode failed: %v", err)
		} else if decodedUser, err := protocol.DecodeUTF16(decoded); err != nil {
			log.Printf("Rdg-User-Id UTF-16 decode failed: %v", err)
		} else {
			log.Printf("Rdg-User-Id decoded: %q", decodedUser)
		}
	}
	path := ""
	if r.URL != nil {
		path = r.URL.Path
	}
	log.Printf(
		"NTLM auth request: method=%s path=%s remote=%s conn_id=%s ua=%q auth_present=%t",
		r.Method,
		path,
		r.RemoteAddr,
		r.Header.Get("Rdg-Connection-Id"),
		r.UserAgent(),
		authHeader != "",
	)
	if authHeader != "" {
		scheme, token := splitAuthHeader(authHeader)
		if scheme != "" && (strings.EqualFold(scheme, "NTLM") || strings.EqualFold(scheme, "Negotiate")) {
			canonicalScheme := canonicalAuthScheme(scheme)
			log.Printf("NTLM auth header: scheme=%s token_len=%d", canonicalScheme, len(token))
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
			log.Printf(
				"NTLM auth token: scheme=%s msg_type=%d decoded_len=%d",
				canonicalScheme,
				msgType,
				len(ntlmToken),
			)
			switch msgType {
			case ntlmMessageTypeNegotiate:
				flags, err := parseNTLMNegotiateFlags(ntlmToken)
				if err != nil {
					log.Printf("NTLM negotiate parse failed from %s: %v", r.RemoteAddr, err)
					return "", a.ntlmChallengeError(r, canonicalScheme, nil)
				}
				log.Printf("NTLM negotiate flags: 0x%x", flags)
				return "", a.ntlmChallengeError(r, canonicalScheme, &flags)
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

func (a *StaticAuth) ntlmChallengeError(r *http.Request, scheme string, clientFlags *uint32) error {
	challenge, err := a.issueNTLMChallenge(r, clientFlags)
	if err != nil {
		return err
	}
	if scheme == "" {
		scheme = "NTLM"
	}
	log.Printf("NTLM auth challenge: scheme=%s key=%s", scheme, NtlmChallengeKey(r))
	return AuthChallenge{Header: scheme + " " + challenge}
}

func (a *StaticAuth) issueNTLMChallenge(r *http.Request, clientFlags *uint32) (string, error) {
	serverChallenge := make([]byte, 8)
	if _, err := rand.Read(serverChallenge); err != nil {
		return "", err
	}
	targetName := ntlmTargetName
	if host := strings.TrimSpace(r.Host); host != "" {
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		}
		if host != "" {
			targetName = host
		}
	}
	forceTargetInfo := true
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-WebSocket-Protocol")), "binary") {
		forceTargetInfo = false
	}
	msg, err := buildNTLMChallengeMessage(serverChallenge, targetName, clientFlags, forceTargetInfo)
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
		log.Printf("NTLM challenge lookup: empty cache key=%s", key)
		return nil, false
	}
	state, ok := a.Challenges[key]
	if !ok {
		log.Printf("NTLM challenge lookup miss: key=%s cache=%d", key, len(a.Challenges))
		return nil, false
	}
	delete(a.Challenges, key)
	if now.Sub(state.IssuedAt) > ntlmChallengeTTL {
		log.Printf(
			"NTLM challenge expired: key=%s age=%s",
			key,
			now.Sub(state.IssuedAt).Truncate(time.Millisecond),
		)
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
		return "", a.ntlmChallengeError(r, scheme, nil)
	}
	log.Printf(
		"NTLM authenticate message: user=%q domain=%q flags=0x%x key=%s",
		msg.UserName,
		msg.DomainName,
		msg.NegotiateFlags,
		NtlmChallengeKey(r),
	)
	challenge, ok := a.takeNTLMChallenge(r)
	if !ok {
		log.Printf("Missing NTLM challenge for %s", NtlmChallengeKey(r))
		return "", a.ntlmChallengeError(r, scheme, nil)
	}

	if a.SessionManager == nil {
		log.Printf("NTLM auth failed, session manager not configured")
		return "", a.ntlmChallengeError(r, scheme, nil)
	}

	userLdap, ok := a.SessionManager.GetSessionFromUserName(msg.UserName)
	if !ok {
		log.Printf("NTLM auth failed, user %q not found", msg.UserName)
		return "", a.ntlmChallengeError(r, scheme, nil)
	}

	if !verifyNTLMv2Response(challenge, userLdap.User.GetNtlmPassword(), msg.NtChallengeResponse) {
		log.Printf(
			"NTLM auth failed for user=%q domain=%q key=%s response_len=%d",
			msg.UserName,
			msg.DomainName,
			NtlmChallengeKey(r),
			len(msg.NtChallengeResponse),
		)
		return "", a.ntlmChallengeError(r, scheme, nil)
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
