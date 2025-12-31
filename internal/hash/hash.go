package hash

import (
	"crypto/hmac"
	"crypto/md5"
	"remotegateway/internal/rdpgw/protocol"
	"strings"

	//nolint:staticcheck // MD4 is required for NTLM compatibility
	"golang.org/x/crypto/md4"
)

func HmacMD5(key []byte, data ...[]byte) []byte {
	mac := hmac.New(md5.New, key)
	for _, d := range data {
		_, _ = mac.Write(d)
	}
	return mac.Sum(nil)
}

func NtlmV2Hash(password, username, domain string) []byte {
	return HmacMD5(ntlmHash(password), protocol.EncodeUTF16(strings.ToUpper(username)+domain))
}

func ntlmHash(password string) []byte {
	hash := md4.New()
	_, _ = hash.Write(protocol.EncodeUTF16(password))
	return hash.Sum(nil)
}
