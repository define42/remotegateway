package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf16"

	//nolint:staticcheck // MD4 is required for NTLM compatibility
	"golang.org/x/crypto/md4"
)

const (
	ntlmSignature = "NTLMSSP\x00"

	ntlmMessageTypeNegotiate     uint32 = 1
	ntlmMessageTypeChallenge     uint32 = 2
	ntlmMessageTypeAuthenticate  uint32 = 3
	ntlmNegotiateUnicode         uint32 = 1 << 0
	ntlmNegotiateRequestTarget   uint32 = 1 << 2
	ntlmNegotiateNTLM            uint32 = 1 << 9
	ntlmNegotiateExtendedSession uint32 = 1 << 19
	ntlmNegotiateTargetInfo      uint32 = 1 << 23
	ntlmChallengeFlags                  = ntlmNegotiateUnicode | ntlmNegotiateNTLM | ntlmNegotiateRequestTarget | ntlmNegotiateExtendedSession | ntlmNegotiateTargetInfo
	ntlmTargetName                      = "RDPGW"
	ntlmChallengeTTL                    = 2 * time.Minute
)

const (
	ntlmAvIDMsvAvEOL       uint16 = 0
	ntlmAvIDMsvAvTimestamp uint16 = 7
)

type ntlmChallengeState struct {
	challenge []byte
	issuedAt  time.Time
}

func NtlmChallengeKey(r *http.Request) string {
	if id := strings.TrimSpace(r.Header.Get("Rdg-Connection-Id")); id != "" {
		return "rdg:" + id
	}
	return "remote:" + r.RemoteAddr
}

func NtlmMessageType(data []byte) (uint32, error) {
	if len(data) < 12 {
		return 0, errors.New("NTLM message too short")
	}
	if !bytes.Equal(data[:8], []byte(ntlmSignature)) {
		return 0, errors.New("invalid NTLM signature")
	}
	return binary.LittleEndian.Uint32(data[8:12]), nil
}

func ExtractNTLMToken(data []byte) ([]byte, error) {
	if len(data) >= 12 && bytes.Equal(data[:8], []byte(ntlmSignature)) {
		return data, nil
	}
	idx := bytes.Index(data, []byte(ntlmSignature))
	if idx < 0 {
		return nil, errors.New("NTLM signature not found")
	}
	token := data[idx:]
	if _, err := NtlmMessageType(token); err != nil {
		return nil, err
	}
	return token, nil
}

type ntlmMessageHeader struct {
	Signature   [8]byte
	MessageType uint32
}

func (h ntlmMessageHeader) IsValid() bool {
	return bytes.Equal(h.Signature[:], []byte(ntlmSignature)) &&
		h.MessageType > 0 && h.MessageType < 4
}

func newNTLMMessageHeader(messageType uint32) ntlmMessageHeader {
	var sig [8]byte
	copy(sig[:], []byte(ntlmSignature))
	return ntlmMessageHeader{Signature: sig, MessageType: messageType}
}

type ntlmVarField struct {
	Len          uint16
	MaxLen       uint16
	BufferOffset uint32
}

func (f ntlmVarField) ReadFrom(buffer []byte) ([]byte, error) {
	if len(buffer) < int(f.BufferOffset+uint32(f.Len)) {
		return nil, errors.New("NTLM var field exceeds buffer")
	}
	return buffer[f.BufferOffset : f.BufferOffset+uint32(f.Len)], nil
}

func (f ntlmVarField) ReadStringFrom(buffer []byte, unicode bool) (string, error) {
	d, err := f.ReadFrom(buffer)
	if err != nil {
		return "", err
	}
	if unicode {
		return fromUnicode(d)
	}
	return string(d), nil
}

func newNTLMVarField(ptr *int, fieldsize int) ntlmVarField {
	f := ntlmVarField{
		Len:          uint16(fieldsize),
		MaxLen:       uint16(fieldsize),
		BufferOffset: uint32(*ptr),
	}
	*ptr += fieldsize
	return f
}

func fromUnicode(d []byte) (string, error) {
	if len(d)%2 != 0 {
		return "", errors.New("invalid UTF-16LE length")
	}
	s := make([]uint16, len(d)/2)
	if err := binary.Read(bytes.NewReader(d), binary.LittleEndian, &s); err != nil {
		return "", err
	}
	return string(utf16.Decode(s)), nil
}

func toUnicode(s string) []byte {
	uints := utf16.Encode([]rune(s))
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, &uints)
	return b.Bytes()
}

type ntlmAuthenticateMessageFields struct {
	Header                    ntlmMessageHeader
	LmChallengeResponse       ntlmVarField
	NtChallengeResponse       ntlmVarField
	DomainName                ntlmVarField
	UserName                  ntlmVarField
	Workstation               ntlmVarField
	EncryptedRandomSessionKey ntlmVarField
	NegotiateFlags            uint32
}

type ntlmAuthenticateMessage struct {
	UserName            string
	DomainName          string
	LmChallengeResponse []byte
	NtChallengeResponse []byte
	NegotiateFlags      uint32
}

func ParseNTLMAuthenticateMessage(data []byte) (*ntlmAuthenticateMessage, error) {
	if len(data) < 64 {
		return nil, errors.New("NTLM authenticate message too short")
	}
	var fields ntlmAuthenticateMessageFields
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &fields); err != nil {
		return nil, err
	}
	if !fields.Header.IsValid() || fields.Header.MessageType != ntlmMessageTypeAuthenticate {
		return nil, errors.New("invalid NTLM authenticate message")
	}
	unicode := fields.NegotiateFlags&ntlmNegotiateUnicode != 0
	domain, err := fields.DomainName.ReadStringFrom(data, unicode)
	if err != nil {
		return nil, err
	}
	user, err := fields.UserName.ReadStringFrom(data, unicode)
	if err != nil {
		return nil, err
	}
	lmResponse, err := fields.LmChallengeResponse.ReadFrom(data)
	if err != nil {
		return nil, err
	}
	ntResponse, err := fields.NtChallengeResponse.ReadFrom(data)
	if err != nil {
		return nil, err
	}
	if len(ntResponse) < 16 {
		return nil, errors.New("NTLM response too short")
	}
	return &ntlmAuthenticateMessage{
		UserName:            user,
		DomainName:          domain,
		LmChallengeResponse: lmResponse,
		NtChallengeResponse: ntResponse,
		NegotiateFlags:      fields.NegotiateFlags,
	}, nil
}

type ntlmChallengeMessageFields struct {
	Header          ntlmMessageHeader
	TargetName      ntlmVarField
	NegotiateFlags  uint32
	ServerChallenge [8]byte
	Reserved        [8]byte
	TargetInfo      ntlmVarField
}

func BuildNTLMChallengeMessage(serverChallenge []byte, targetName string) ([]byte, error) {
	if len(serverChallenge) != 8 {
		return nil, errors.New("invalid NTLM challenge length")
	}
	payloadOffset := 48
	targetNameBytes := toUnicode(targetName)
	targetInfoBytes := buildNTLMTargetInfo(time.Now())
	msg := ntlmChallengeMessageFields{
		Header:         newNTLMMessageHeader(ntlmMessageTypeChallenge),
		TargetName:     newNTLMVarField(&payloadOffset, len(targetNameBytes)),
		NegotiateFlags: ntlmChallengeFlags,
		TargetInfo:     newNTLMVarField(&payloadOffset, len(targetInfoBytes)),
	}
	copy(msg.ServerChallenge[:], serverChallenge)

	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, &msg); err != nil {
		return nil, err
	}
	if _, err := b.Write(targetNameBytes); err != nil {
		return nil, err
	}
	if _, err := b.Write(targetInfoBytes); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func buildNTLMTargetInfo(now time.Time) []byte {
	timestamp := make([]byte, 8)
	ft := uint64(now.UnixNano()) / 100
	ft += 116444736000000000
	binary.LittleEndian.PutUint64(timestamp, ft)

	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, ntlmAvIDMsvAvTimestamp)
	_ = binary.Write(&b, binary.LittleEndian, uint16(len(timestamp)))
	_, _ = b.Write(timestamp)
	_ = binary.Write(&b, binary.LittleEndian, ntlmAvIDMsvAvEOL)
	_ = binary.Write(&b, binary.LittleEndian, uint16(0))
	return b.Bytes()
}

func NtlmV2Hash(password, username, domain string) []byte {
	return hmacMD5(ntlmHash(password), toUnicode(strings.ToUpper(username)+domain))
}

func ntlmHash(password string) []byte {
	hash := md4.New()
	_, _ = hash.Write(toUnicode(password))
	return hash.Sum(nil)
}

func VerifyNTLMv2Response(serverChallenge, ntlmV2Hash, ntResponse []byte) bool {
	if len(serverChallenge) != 8 || len(ntResponse) < 16 {
		return false
	}
	proof := ntResponse[:16]
	temp := ntResponse[16:]
	expected := hmacMD5(ntlmV2Hash, serverChallenge, temp)
	return hmac.Equal(expected, proof)
}

func hmacMD5(key []byte, data ...[]byte) []byte {
	mac := hmac.New(md5.New, key)
	for _, d := range data {
		_, _ = mac.Write(d)
	}
	return mac.Sum(nil)
}
