package ntlm

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"remotegateway/internal/hash"
	"remotegateway/internal/rdpgw/protocol"
	"testing"
	"time"
)

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
	got, err := field.readStringFrom(buf, false)
	if err != nil {
		t.Fatalf("expected string read: %v", err)
	}
	if got != "abc" {
		t.Fatalf("expected abc, got %q", got)
	}

	unicode := protocol.EncodeUTF16("bob")
	buf = append(make([]byte, 2), unicode...)
	field = ntlmVarField{Len: uint16(len(unicode)), MaxLen: uint16(len(unicode)), BufferOffset: 2}
	got, err = field.readStringFrom(buf, true)
	if err != nil {
		t.Fatalf("expected unicode string read: %v", err)
	}
	if got != "bob" {
		t.Fatalf("expected bob, got %q", got)
	}

	badField := ntlmVarField{Len: 4, MaxLen: 4, BufferOffset: 5}
	if _, err := badField.readFrom([]byte("short")); err == nil {
		t.Fatalf("expected error for out-of-bounds var field")
	}
}

func TestFromUnicodeOddLength(t *testing.T) {
	if _, err := protocol.DecodeUTF16([]byte{0x00}); err == nil {
		t.Fatalf("expected error for odd-length UTF-16 data")
	}
}

func TestParseNTLMAuthenticateMessage(t *testing.T) {
	user := "User"
	domain := "Domain"
	ntResponse := bytes.Repeat([]byte{0xAA}, 16)
	msg := BuildTestNTLMAuthenticateMessage(user, domain, ntResponse, true)

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

	shortResponseMsg := BuildTestNTLMAuthenticateMessage(user, domain, []byte{0x01, 0x02}, true)
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

	target, err := fields.TargetName.readStringFrom(msg, true)
	if err != nil {
		t.Fatalf("expected target name: %v", err)
	}
	if target != ntlmTargetName {
		t.Fatalf("expected target %q, got %q", ntlmTargetName, target)
	}

	targetInfo, err := fields.TargetInfo.readFrom(msg)
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
	ntlmHash := hash.NtlmV2Hash("password", "User", "Domain")
	temp := []byte{0x10, 0x20, 0x30, 0x40}
	proof := hash.HmacMD5(ntlmHash, serverChallenge, temp)
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
	if got := NtlmChallengeKey(req); got != "rdg:abc" {
		t.Fatalf("expected rdg key, got %q", got)
	}

	req = &http.Request{RemoteAddr: "1.2.3.4:3389", Header: http.Header{}}
	if got := NtlmChallengeKey(req); got != "remote:1.2.3.4:3389" {
		t.Fatalf("expected remote key, got %q", got)
	}
}

func TestTakeNTLMChallenge(t *testing.T) {
	req := &http.Request{RemoteAddr: "1.2.3.4:3389", Header: http.Header{}}
	key := NtlmChallengeKey(req)
	original := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	auth := &StaticAuth{
		Challenges: map[string]NtlmChallengeState{
			key: {
				Challenge: original,
				IssuedAt:  time.Now(),
			},
		},
	}

	challenge, ok := auth.takeNTLMChallenge(req)
	if !ok {
		t.Fatalf("expected challenge to be returned")
	}
	if !bytes.Equal(challenge, original) {
		t.Fatalf("expected challenge to match original")
	}
	challenge[0] ^= 0xFF
	if bytes.Equal(challenge, original) {
		t.Fatalf("expected challenge to be copied")
	}

	if _, ok := auth.takeNTLMChallenge(req); ok {
		t.Fatalf("expected challenge to be removed after take")
	}

	expiredAuth := &StaticAuth{
		Challenges: map[string]NtlmChallengeState{
			key: {
				Challenge: original,
				IssuedAt:  time.Now().Add(-ntlmChallengeTTL - time.Second),
			},
		},
	}
	if _, ok := expiredAuth.takeNTLMChallenge(req); ok {
		t.Fatalf("expected expired challenge to be rejected")
	}
	if len(expiredAuth.Challenges) != 0 {
		t.Fatalf("expected expired challenge to be pruned")
	}

	emptyAuth := &StaticAuth{}
	if _, ok := emptyAuth.takeNTLMChallenge(req); ok {
		t.Fatalf("expected missing challenge to be rejected")
	}
}
