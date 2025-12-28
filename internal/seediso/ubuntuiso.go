package seediso

import (
	"fmt"
	"io"
	"os"

	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
	"libvirt.org/go/libvirt"
)

func CreateUbuntuSeedISOToPool(
	conn *libvirt.Connect,
	poolName string,
	volumeName string,
	username string,
	password string,
	hostname string,
) error {

	// 1. Generate password hash
	passSha, err := CloudInitPasswordHash(password)
	if err != nil {
		return err
	}

	// 2. Build cloud-init data
	userData := []byte(`#cloud-config
users:
  - name: ` + username + `
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    passwd: ` + passSha + `
ssh_pwauth: true
`)

	fmt.Println("userData:", string(userData))

	metaData := []byte(`instance-id: ubuntu-seed
local-hostname: ` + hostname + `
`)

	// 3. Create temporary ISO
	tmpFile, err := os.CreateTemp("", "seed-*.iso")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	iso := SeedISO{
		UserData: userData,
		MetaData: metaData,
	}

	if err := iso.Create(tmpFile.Name()); err != nil {
		return err
	}

	info, err := os.Stat(tmpFile.Name())
	if err != nil {
		return err
	}

	// 4. Lookup storage pool
	pool, err := conn.LookupStoragePoolByName(poolName)
	if err != nil {
		return err
	}
	defer func() {
		if err := pool.Free(); err != nil {
			fmt.Println("pool free error:", err)
		}
	}()

	// 5. Create volume for ISO
	volXML := fmt.Sprintf(`
<volume>
  <name>%s</name>
  <capacity unit="bytes">%d</capacity>
  <target>
    <format type="raw"/>
  </target>
</volume>`, volumeName, info.Size())

	vol, err := pool.StorageVolCreateXML(volXML, 0)
	if err != nil {
		return err
	}
	defer func() {
		_ = vol.Free()
	}()

	// 6. Upload ISO into the volume
	src, err := os.Open(tmpFile.Name())
	if err != nil {
		return err
	}
	defer src.Close()

	stream, err := conn.NewStream(0)
	if err != nil {
		return err
	}
	defer func() {
		_ = stream.Free()
	}()

	if err := vol.Upload(stream, 0, uint64(info.Size()), 0); err != nil {
		return err
	}

	if err := stream.SendAll(func(_ *libvirt.Stream, nbytes int) ([]byte, error) {
		buf := make([]byte, nbytes)
		n, err := src.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		return buf[:n], nil
	}); err != nil {
		_ = stream.Abort()
		return err
	}

	return stream.Finish()
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
