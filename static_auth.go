package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
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
const staticPassword = "testpassword"

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
				ntlmToken, err = extractNTLMToken(decoded)
				if err != nil {
					log.Printf("Negotiate token missing NTLM for %s: %v", r.RemoteAddr, err)
					return "", authChallenge{header: canonicalScheme}
				}
			}
			msgType, err := ntlmMessageType(ntlmToken)
			if err != nil {
				log.Printf("Invalid NTLM message from %s: %v", r.RemoteAddr, err)
				return "", authChallenge{header: canonicalScheme}
			}
			switch msgType {
			case ntlmMessageTypeNegotiate:
				return "", a.ntlmChallengeError(r, canonicalScheme)
			case ntlmMessageTypeAuthenticate:
				user, err := a.verifyNTLMAuthenticate(r, ntlmToken, canonicalScheme, staticUser, staticPassword)
				if err != nil {
					return "", err
				}
				return normalizeUser(user), nil
			default:
				return "", authChallenge{header: canonicalScheme}
			}
		}
	}
	fmt.Println("###################################################")
	return "", errors.New("invalid username or password")

	username, password, ok := r.BasicAuth()
	if !ok {
		return "", errors.New("missing credentials")
	}
	if username != staticUser || password != staticPassword {
		return "", errors.New("invalid username or password")
	}

	return normalizeUser(username), nil
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
