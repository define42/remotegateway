package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNTLMMessageType(t *testing.T) {
	token := buildTestNTLMToken(ntlmMessageTypeNegotiate)
	msgType, err := ntlmMessageType(token)
	if err != nil {
		t.Fatalf("expected message type: %v", err)
	}
	if msgType != ntlmMessageTypeNegotiate {
		t.Fatalf("expected message type %d, got %d", ntlmMessageTypeNegotiate, msgType)
	}

	if _, err := ntlmMessageType(token[:10]); err == nil {
		t.Fatalf("expected error for short message")
	}

	bad := append([]byte(nil), token...)
	bad[0] = 0
	if _, err := ntlmMessageType(bad); err == nil {
		t.Fatalf("expected error for invalid signature")
	}
}

func TestNTLMVarFieldReadStringFrom(t *testing.T) {
	buf := []byte{0, 0, 0, 0, 'a', 'b', 'c'}
	field := ntlmVarField{Len: 3, MaxLen: 3, BufferOffset: 4}
	got, err := field.ReadStringFrom(buf, false)
	if err != nil {
		t.Fatalf("expected string read: %v", err)
	}
	if got != "abc" {
		t.Fatalf("expected abc, got %q", got)
	}

	unicode := toUnicode("bob")
	buf = append(make([]byte, 2), unicode...)
	field = ntlmVarField{Len: uint16(len(unicode)), MaxLen: uint16(len(unicode)), BufferOffset: 2}
	got, err = field.ReadStringFrom(buf, true)
	if err != nil {
		t.Fatalf("expected unicode string read: %v", err)
	}
	if got != "bob" {
		t.Fatalf("expected bob, got %q", got)
	}

	badField := ntlmVarField{Len: 4, MaxLen: 4, BufferOffset: 5}
	if _, err := badField.ReadFrom([]byte("short")); err == nil {
		t.Fatalf("expected error for out-of-bounds var field")
	}
}

func TestFromUnicodeOddLength(t *testing.T) {
	if _, err := fromUnicode([]byte{0x00}); err == nil {
		t.Fatalf("expected error for odd-length UTF-16 data")
	}
}

func TestParseNTLMAuthenticateMessage(t *testing.T) {
	user := "User"
	domain := "Domain"
	ntResponse := bytes.Repeat([]byte{0xAA}, 16)
	msg := buildTestNTLMAuthenticateMessage(user, domain, ntResponse, true)

	parsed, err := parseNTLMAuthenticateMessage(msg)
	if err != nil {
		t.Fatalf("expected parse to succeed: %v", err)
	}
	if parsed.UserName != user {
		t.Fatalf("expected user %q, got %q", user, parsed.UserName)
	}
	if parsed.DomainName != domain {
		t.Fatalf("expected domain %q, got %q", domain, parsed.DomainName)
	}
	if !bytes.Equal(parsed.NtChallengeResponse, ntResponse) {
		t.Fatalf("expected NT response to match input")
	}

	shortResponseMsg := buildTestNTLMAuthenticateMessage(user, domain, []byte{0x01, 0x02}, true)
	if _, err := parseNTLMAuthenticateMessage(shortResponseMsg); err == nil {
		t.Fatalf("expected error for short NT response")
	}

	invalidHeader := append([]byte(nil), msg...)
	invalidHeader[0] = 0
	if _, err := parseNTLMAuthenticateMessage(invalidHeader); err == nil {
		t.Fatalf("expected error for invalid header")
	}
}

func TestBuildNTLMChallengeMessage(t *testing.T) {
	challenge := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	msg, err := buildNTLMChallengeMessage(challenge, ntlmTargetName)
	if err != nil {
		t.Fatalf("expected build to succeed: %v", err)
	}

	var fields ntlmChallengeMessageFields
	if err := binary.Read(bytes.NewReader(msg), binary.LittleEndian, &fields); err != nil {
		t.Fatalf("expected challenge header to parse: %v", err)
	}
	if !fields.Header.IsValid() || fields.Header.MessageType != ntlmMessageTypeChallenge {
		t.Fatalf("expected valid challenge header")
	}

	target, err := fields.TargetName.ReadStringFrom(msg, true)
	if err != nil {
		t.Fatalf("expected target name: %v", err)
	}
	if target != ntlmTargetName {
		t.Fatalf("expected target %q, got %q", ntlmTargetName, target)
	}

	targetInfo, err := fields.TargetInfo.ReadFrom(msg)
	if err != nil {
		t.Fatalf("expected target info: %v", err)
	}
	if len(targetInfo) < 16 {
		t.Fatalf("expected target info length >= 16, got %d", len(targetInfo))
	}
	if got := binary.LittleEndian.Uint16(targetInfo[0:2]); got != ntlmAvIDMsvAvTimestamp {
		t.Fatalf("expected timestamp AV ID, got %d", got)
	}
	if got := binary.LittleEndian.Uint16(targetInfo[2:4]); got != 8 {
		t.Fatalf("expected timestamp length 8, got %d", got)
	}
	end := targetInfo[len(targetInfo)-4:]
	if got := binary.LittleEndian.Uint16(end[0:2]); got != ntlmAvIDMsvAvEOL {
		t.Fatalf("expected EOL AV ID, got %d", got)
	}
	if got := binary.LittleEndian.Uint16(end[2:4]); got != 0 {
		t.Fatalf("expected EOL length 0, got %d", got)
	}

	if _, err := buildNTLMChallengeMessage([]byte{1, 2, 3}, ntlmTargetName); err == nil {
		t.Fatalf("expected error for invalid challenge length")
	}
}

func TestVerifyNTLMv2Response(t *testing.T) {
	serverChallenge := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ntlmHash := ntlmV2Hash("password", "User", "Domain")
	temp := []byte{0x10, 0x20, 0x30, 0x40}
	proof := hmacMD5(ntlmHash, serverChallenge, temp)
	ntResponse := append(append([]byte(nil), proof...), temp...)

	if !verifyNTLMv2Response(serverChallenge, ntlmHash, ntResponse) {
		t.Fatalf("expected NTLMv2 response to verify")
	}
	if verifyNTLMv2Response(serverChallenge, ntlmHash, ntResponse[:10]) {
		t.Fatalf("expected short response to fail verification")
	}
	if verifyNTLMv2Response(serverChallenge[:7], ntlmHash, ntResponse) {
		t.Fatalf("expected short challenge to fail verification")
	}
}

func TestNTLMChallengeKey(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "1.2.3.4:3389",
		Header:     http.Header{"Rdg-Connection-Id": []string{"abc"}},
	}
	if got := ntlmChallengeKey(req); got != "rdg:abc" {
		t.Fatalf("expected rdg key, got %q", got)
	}

	req = &http.Request{RemoteAddr: "1.2.3.4:3389", Header: http.Header{}}
	if got := ntlmChallengeKey(req); got != "remote:1.2.3.4:3389" {
		t.Fatalf("expected remote key, got %q", got)
	}
}

func TestVerifyNTLMAuthenticateSuccess(t *testing.T) {
	challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	req := &http.Request{RemoteAddr: "1.2.3.4:3389", Header: http.Header{}}
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

	user, err := auth.verifyNTLMAuthenticate(req, msg, "NTLM", staticUser, staticPassword)
	if err != nil {
		t.Fatalf("expected NTLM auth to succeed: %v", err)
	}
	if user != staticUser {
		t.Fatalf("expected user %q, got %q", staticUser, user)
	}
}

func TestVerifyNTLMAuthenticateMissingChallenge(t *testing.T) {
	auth := &StaticAuth{}
	req := &http.Request{RemoteAddr: "1.2.3.4:3389", Header: http.Header{}}
	domain := "DOMAIN"
	ntResponse := buildTestNTLMv2Response([]byte{1, 2, 3, 4, 5, 6, 7, 8}, staticUser, domain, staticPassword)
	msg := buildTestNTLMAuthenticateMessage(staticUser, domain, ntResponse, true)

	user, err := auth.verifyNTLMAuthenticate(req, msg, "NTLM", staticUser, staticPassword)
	if err == nil {
		t.Fatalf("expected challenge error for missing NTLM challenge")
	}
	if user != "" {
		t.Fatalf("expected empty user on failure, got %q", user)
	}
	var challengeErr authChallenge
	if !errors.As(err, &challengeErr) {
		t.Fatalf("expected auth challenge error, got %T", err)
	}
	if !strings.HasPrefix(challengeErr.header, "NTLM ") {
		t.Fatalf("expected NTLM challenge header, got %q", challengeErr.header)
	}
}

func TestVerifyNTLMAuthenticateInvalidResponse(t *testing.T) {
	challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	req := &http.Request{RemoteAddr: "1.2.3.4:3389", Header: http.Header{}}
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
	ntResponse[0] ^= 0xFF
	msg := buildTestNTLMAuthenticateMessage(staticUser, domain, ntResponse, true)

	user, err := auth.verifyNTLMAuthenticate(req, msg, "NTLM", staticUser, staticPassword)
	if err == nil {
		t.Fatalf("expected NTLM auth failure for invalid response")
	}
	if user != "" {
		t.Fatalf("expected empty user on failure, got %q", user)
	}
	var challengeErr authChallenge
	if !errors.As(err, &challengeErr) {
		t.Fatalf("expected auth challenge error, got %T", err)
	}
}

func buildTestNTLMv2Response(challenge []byte, user, domain, password string) []byte {
	ntlmHash := ntlmV2Hash(password, user, domain)
	temp := []byte{0x10, 0x20, 0x30, 0x40}
	proof := hmacMD5(ntlmHash, challenge, temp)
	return append(append([]byte(nil), proof...), temp...)
}

func buildTestNTLMAuthenticateMessage(user, domain string, ntResponse []byte, unicode bool) []byte {
	lmResponse := []byte{0x01, 0x02, 0x03}
	payloadOffset := 64
	domainBytes := []byte(domain)
	userBytes := []byte(user)
	if unicode {
		domainBytes = toUnicode(domain)
		userBytes = toUnicode(user)
	}

	msg := ntlmAuthenticateMessageFields{
		Header:                    newNTLMMessageHeader(ntlmMessageTypeAuthenticate),
		LmChallengeResponse:       newNTLMVarField(&payloadOffset, len(lmResponse)),
		NtChallengeResponse:       newNTLMVarField(&payloadOffset, len(ntResponse)),
		DomainName:                newNTLMVarField(&payloadOffset, len(domainBytes)),
		UserName:                  newNTLMVarField(&payloadOffset, len(userBytes)),
		Workstation:               newNTLMVarField(&payloadOffset, 0),
		EncryptedRandomSessionKey: newNTLMVarField(&payloadOffset, 0),
	}
	if unicode {
		msg.NegotiateFlags = ntlmNegotiateUnicode
	}

	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, &msg)
	_, _ = b.Write(lmResponse)
	_, _ = b.Write(ntResponse)
	_, _ = b.Write(domainBytes)
	_, _ = b.Write(userBytes)
	return b.Bytes()
}
