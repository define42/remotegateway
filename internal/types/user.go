package types

import "remotegateway/internal/hash"

type User struct {
	Name                  string
	NtlmPassword          []byte
	CloudInitPasswordHash string
}

func NewUser(name, password, domain string) (*User, error) {

	cloudInitPassword, err := hash.CloudInitPasswordHash(password)
	if err != nil {
		return nil, err
	}

	return &User{
		Name:                  name,
		NtlmPassword:          hash.NtlmV2Hash(password, name, domain),
		CloudInitPasswordHash: cloudInitPassword,
	}, nil
}

func (u *User) GetName() string {
	return u.Name
}

func (u *User) GetNtlmPassword() []byte {
	return u.NtlmPassword
}

func (u *User) GetCloudInitPasswordHash() string {
	return u.CloudInitPasswordHash
}
