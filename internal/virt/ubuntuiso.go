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
package_update: true
package_upgrade: true
packages:
  - gnome-session
  - gnome-shell
  - gnome-terminal
  - gdm3
  - xrdp
  - xorgxrdp
  - dbus-x11

write_files:
  # Disable Wayland (XRDP requires Xorg)
  - path: /etc/gdm3/custom.conf
    permissions: '0644'
    content: |
      [daemon]
      WaylandEnable=false
      DefaultSession=gnome-xorg.desktop

  # Force GNOME to behave well under XRDP
  - path: /etc/profile.d/gnome-xrdp.sh
    permissions: '0644'
    content: |
      export XDG_SESSION_TYPE=x11
      export GSK_RENDERER=cairo
      export MUTTER_DEBUG_FORCE_KMS_MODE=simple

  # Disable GNOME portal backend globally (avoid timeouts)
  - path: /etc/systemd/user/xdg-desktop-portal-gnome.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Disabled for XRDP

  # Disable AppArmor at kernel level
  - path: /etc/default/grub.d/99-disable-apparmor.cfg
    permissions: '0644'
    content: |
      GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT apparmor=0"

runcmd:
  # Enable XRDP
  - systemctl enable xrdp
  - systemctl restart xrdp

  # Disable AppArmor service immediately (kernel param applies after reboot)
  - systemctl disable --now apparmor || true

  # Mask GNOME portal backend globally
  - systemctl --global mask xdg-desktop-portal-gnome.service

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
