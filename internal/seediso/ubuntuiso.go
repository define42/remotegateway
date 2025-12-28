package seediso

import (
	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
)

func CreateUbuntuSeedISO(isoPath, username, password, hostname string) error {

	passSha, err := CloudInitPasswordHash(password)
	if err != nil {
		return err
	}

	userData := []byte(`#cloud-config
users:
  - name: ` + username + `
    sudo: ALL=(ALL) NOPASSWD:ALL
    passwd: ` + passSha + `
`)

	metaData := []byte(`instance-id: ubuntu-seed
local-hostname: ` + hostname + `
`)

	iso := SeedISO{
		UserData: userData,
		MetaData: metaData,
	}

	if err := iso.Create(isoPath); err != nil {
		return err
	}
	return nil
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
