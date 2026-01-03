package ntlm

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"log"
	"net/http"
	"remotegateway/internal/contextKey"
	"remotegateway/internal/hash"
	"remotegateway/internal/rdpgw/common"
	"remotegateway/internal/rdpgw/protocol"
	"strings"
	"time"
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

type NtlmChallengeState struct {
	Challenge []byte
	IssuedAt  time.Time
}

func NtlmChallengeKey(r *http.Request) string {
	if id := strings.TrimSpace(r.Header.Get("Rdg-Connection-Id")); id != "" {
		return "rdg:" + id
	}
	return "remote:" + r.RemoteAddr
}

func ntlmMessageType(data []byte) (uint32, error) {
	if len(data) < 12 {
		return 0, errors.New("NTLM message too short")
	}
	if !bytes.Equal(data[:8], []byte(ntlmSignature)) {
		return 0, errors.New("invalid NTLM signature")
	}
	return binary.LittleEndian.Uint32(data[8:12]), nil
}

func extractNTLMToken(data []byte) ([]byte, error) {
	if len(data) >= 12 && bytes.Equal(data[:8], []byte(ntlmSignature)) {
		return data, nil
	}
	idx := bytes.Index(data, []byte(ntlmSignature))
	if idx < 0 {
		return nil, errors.New("NTLM signature not found")
	}
	token := data[idx:]
	if _, err := ntlmMessageType(token); err != nil {
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

func (f ntlmVarField) readFrom(buffer []byte) ([]byte, error) {
	if len(buffer) < int(f.BufferOffset+uint32(f.Len)) {
		return nil, errors.New("NTLM var field exceeds buffer")
	}
	return buffer[f.BufferOffset : f.BufferOffset+uint32(f.Len)], nil
}

func (f ntlmVarField) readStringFrom(buffer []byte, unicode bool) (string, error) {
	d, err := f.readFrom(buffer)
	if err != nil {
		return "", err
	}
	if unicode {
		return protocol.DecodeUTF16(d)
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

func parseNTLMAuthenticateMessage(data []byte) (*ntlmAuthenticateMessage, error) {
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
	domain, err := fields.DomainName.readStringFrom(data, unicode)
	if err != nil {
		return nil, err
	}
	user, err := fields.UserName.readStringFrom(data, unicode)
	if err != nil {
		return nil, err
	}
	lmResponse, err := fields.LmChallengeResponse.readFrom(data)
	if err != nil {
		return nil, err
	}
	ntResponse, err := fields.NtChallengeResponse.readFrom(data)
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

func buildNTLMChallengeMessage(serverChallenge []byte, targetName string) ([]byte, error) {
	if len(serverChallenge) != 8 {
		return nil, errors.New("invalid NTLM challenge length")
	}
	payloadOffset := 48
	targetNameBytes := protocol.EncodeUTF16(targetName)
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

func verifyNTLMv2Response(serverChallenge, ntlmV2Hash, ntResponse []byte) bool {
	if len(serverChallenge) != 8 || len(ntResponse) < 16 {
		return false
	}
	proof := ntResponse[:16]
	temp := ntResponse[16:]
	expected := hash.HmacMD5(ntlmV2Hash, serverChallenge, temp)
	return hmac.Equal(expected, proof)
}

func buildTestNTLMToken(messageType uint32) []byte {
	token := make([]byte, 12)
	copy(token[:8], []byte(ntlmSignature))
	binary.LittleEndian.PutUint32(token[8:12], messageType)
	return token
}

func BasicAuthMiddleware(authenticator *StaticAuth, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := authenticator.Authenticate(r.Context(), r)
		if err != nil {
			var challenge AuthChallenge
			if errors.As(err, &challenge) {
				scheme, token := splitAuthHeader(challenge.Header)
				authHeaders := []string{challenge.Header}
				if strings.EqualFold(scheme, "Negotiate") && token != "" {
					authHeaders = append(authHeaders, "NTLM "+token)
				}
				isRDG := r.URL.Path == "/remoteDesktopGateway" || strings.HasPrefix(r.URL.Path, "/remoteDesktopGateway/")
				if !isRDG {
					authHeaders = append(authHeaders, `Basic realm="rdpgw"`)
				}
				for _, header := range authHeaders {
					w.Header().Add("WWW-Authenticate", header)
				}
				log.Printf(
					"Gateway auth challenge: scheme=%s remote=%s client_ip=%s method=%s path=%s conn_id=%s www_authenticate=%q",
					scheme,
					r.RemoteAddr,
					common.GetClientIp(r.Context()),
					r.Method,
					r.URL.Path,
					r.Header.Get("Rdg-Connection-Id"),
					strings.Join(authHeaders, " | "),
				)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			log.Printf(
				"Gateway auth failed: remote=%s client_ip=%s method=%s path=%s conn_id=%s err=%v",
				r.RemoteAddr,
				common.GetClientIp(r.Context()),
				r.Method,
				r.URL.Path,
				r.Header.Get("Rdg-Connection-Id"),
				err,
			)
			if r.URL.Path != "/remoteDesktopGateway" && !strings.HasPrefix(r.URL.Path, "/remoteDesktopGateway/") {
				w.Header().Set("WWW-Authenticate", `Basic realm="rdpgw"`)
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := contextKey.WithAuthUser(r.Context(), user)
		log.Printf(
			"Gateway connect: user=%s remote=%s client_ip=%s method=%s path=%s conn_id=%s ua=%q",
			user,
			r.RemoteAddr,
			common.GetClientIp(r.Context()),
			r.Method,
			r.URL.Path,
			r.Header.Get("Rdg-Connection-Id"),
			r.UserAgent(),
		)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func BuildTestNTLMv2Response(challenge []byte, user, domain, password string) []byte {
	ntlmHash := hash.NtlmV2Hash(password, user, domain)
	temp := []byte{0x10, 0x20, 0x30, 0x40}
	proof := hash.HmacMD5(ntlmHash, challenge, temp)
	return append(append([]byte(nil), proof...), temp...)
}

func BuildTestNTLMAuthenticateMessage(user, domain string, ntResponse []byte, unicode bool) []byte {
	lmResponse := []byte{0x01, 0x02, 0x03}
	payloadOffset := 64
	domainBytes := []byte(domain)
	userBytes := []byte(user)
	if unicode {
		domainBytes = protocol.EncodeUTF16(domain)
		userBytes = protocol.EncodeUTF16(user)
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
