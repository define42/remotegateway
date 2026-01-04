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
  - xfce4
  - xfce4-goodies
  - xfce4-terminal
  - lightdm
  - lightdm-gtk-greeter
  - xauth
  - xserver-xorg-input-libinput
  - xserver-xorg-legacy
  - xrdp
  - xorgxrdp
  - dbus-x11

write_files:
  # Use XFCE for XRDP sessions
  - path: /home/` + username + `/.xsession
    owner: ` + username + `:` + username + `
    permissions: '0755'
    content: |
      startxfce4

  # LightDM config for XFCE
  - path: /etc/lightdm/lightdm.conf.d/50-xfce.conf
    permissions: '0644'
    content: |
      [Seat:*]
      greeter-session=lightdm-gtk-greeter
      user-session=xfce

  # Make LightDM the default display manager
  - path: /etc/X11/default-display-manager
    permissions: '0644'
    content: |
      /usr/sbin/lightdm

  # Allow XRDP to launch Xorg for non-console users
  - path: /etc/X11/Xwrapper.config
    permissions: '0644'
    content: |
      allowed_users=anybody
      needs_root_rights=yes

  # Force XRDP sessions to start XFCE
  - path: /etc/xrdp/startwm.sh
    permissions: '0755'
    content: |
      #!/bin/sh
      if [ -r /etc/profile ]; then
        . /etc/profile
      fi
      if [ -r ~/.profile ]; then
        . ~/.profile
      fi
      exec startxfce4

  # Disable AppArmor at kernel level
  - path: /etc/default/grub.d/99-disable-apparmor.cfg
    permissions: '0644'
    content: |
      GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT apparmor=0"

  # Reduce Firefox CPU usage under XRDP
  - path: /etc/firefox/policies/policies.json
    permissions: '0644'
    content: |
      {
        "policies": {
          "DisableHardwareAcceleration": true,
          "Preferences": {
            "layers.acceleration.disabled": { "Value": true, "Status": "locked" },
            "gfx.webrender.enabled": { "Value": false, "Status": "locked" },
            "gfx.webrender.all": { "Value": false, "Status": "locked" }
          }
        }
      }

runcmd:
  # Ensure runtime dirs and X authority can be created
  - chmod 1777 /tmp /var/tmp
  - chown -R ` + username + `:` + username + ` /home/` + username + `
  - rm -f /home/` + username + `/.Xauthority /home/` + username + `/.ICEauthority

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
