package hash

import (
	"crypto/hmac"
	"crypto/md5"
	"remotegateway/internal/rdpgw/protocol"
	"strings"

	"github.com/tredoe/osutil/user/crypt/sha512_crypt"

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

// CloudInitPasswordHash generates a /etc/shadow compatible
// SHA-512 ($6$) password hash for cloud-init.
func CloudInitPasswordHash(password string) (string, error) {
	saltGen := sha512_crypt.GetSalt()
	salt := saltGen.GenerateWRounds(16, 5000)
	c := sha512_crypt.New()
	hash, err := c.Generate([]byte(password), salt)
	if err != nil {
		return "", err
	}

	return hash, nil
}
