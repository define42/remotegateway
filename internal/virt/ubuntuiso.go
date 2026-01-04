package virt

import (
	"fmt"
	"io"
	"os"

	"libvirt.org/go/libvirt"
)

func CreateUbuntuSeedISOToPool(
	conn *libvirt.Connect,
	volumeName string,
	username string,
	cloudInitPasswordHash string,
	hostname string,
) error {

	// 2. Build cloud-init data
	userData := []byte(`#cloud-config
output:
  all: '| tee -a /var/log/cloud-init-output.log'
keyboard:
  layout: dk
  variant: ''
users:
  - name: ` + username + `
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    passwd: ` + cloudInitPasswordHash + `
ssh_pwauth: true

runcmd:
  # Ensure runtime dirs and X authority can be created
  - chmod 1777 /tmp /var/tmp
  - test -f /home/` + username + `/.xsession || cp /etc/skel/.xsession /home/` + username + `/.xsession
  - chown -R ` + username + `:` + username + ` /home/` + username + `
  - rm -f /home/` + username + `/.Xauthority /home/` + username + `/.ICEauthority

  # Apply Firefox policy for Snap (Ubuntu default)
  - mkdir -p /var/snap/firefox/common/policies
  - cp /etc/firefox/policies/policies.json /var/snap/firefox/common/policies/policies.json

  # Enable XRDP
  - usermod -aG ssl-cert xrdp
  - systemctl enable xrdp
  - systemctl restart xrdp

  # Prefer LightDM/XFCE for local UI
  - systemctl disable --now gdm3 || true
  - systemctl mask gdm3 || true
  - systemctl set-default graphical.target || true

  # Disable AppArmor service immediately (kernel param applies after reboot)
  - systemctl disable --now apparmor || true

  # Update GRUB and reboot to apply kernel params
  - update-grub
  - reboot
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
	pool, err := conn.LookupStoragePoolByName(DEFAULT_VIRT_STORAGE)
	if err != nil {
		return err
	}
	defer func() {
		if err := pool.Free(); err != nil {
			fmt.Println("pool free error:", err)
		}
	}()

	// 5. Create volume for ISO
	permXML, err := storageVolPermissionsXML()
	if err != nil {
		return err
	}
	pathXML := ""
	if permXML != "" {
		pathXML, err = storageVolPathXML(pool, volumeName)
		if err != nil {
			return err
		}
	}
	volXML := fmt.Sprintf(`
<volume>
  <name>%s</name>
  <capacity unit="bytes">%d</capacity>
  <target>
    <format type="raw"/>%s%s
  </target>
</volume>`, volumeName, info.Size(), pathXML, permXML)

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
