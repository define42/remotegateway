package qemu_domain

import "fmt"

func UbuntuDomain() string {

	return fmt.Sprintf(`<domain type='kvm'>
  <name>ubuntu-cloudinit-desktop</name>
  <memory unit='MiB'>4096</memory>
  <currentMemory unit='MiB'>4096</currentMemory>
  <vcpu placement='static'>4</vcpu>

  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
  </os>

  <cpu mode='host-passthrough'/>

  <features>
    <acpi/>
    <apic/>
    <vmport state='off'/>
  </features>

  <clock offset='utc'/>

  <devices>
    <!-- Main disk -->
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/libvirt/images/ubuntu-22.04-server-cloudimg-amd64.img'/>
      <target dev='vda' bus='virtio'/>
    </disk>

    <!-- cloud-init seed ISO -->
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='/var/lib/libvirt/images/seed.iso'/>
      <target dev='vdb' bus='virtio'/>
      <readonly/>
    </disk>

    <!-- Network (user-mode NAT, like -netdev user) -->
    <interface type='user'>
      <model type='virtio'/>
    </interface>

    <!-- Graphics -->
    <graphics type='spice' autoport='yes'/>

    <!-- Video -->
    <video>
      <model type='virtio' heads='1'/>
    </video>

    <!-- Console -->
    <console type='pty'/>

    <!-- Input -->
    <input type='tablet' bus='usb'/>

    <!-- RNG -->
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
  </devices>
</domain>
<domain type='kvm'>
  <name>ubuntu-cloudinit-desktop</name>
  <memory unit='MiB'>4096</memory>
  <currentMemory unit='MiB'>%d</currentMemory>
  <vcpu placement='static'>4</vcpu>

  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
  </os>

  <cpu mode='host-passthrough'/>

  <features>
    <acpi/>
    <apic/>
    <vmport state='off'/>
  </features>

  <clock offset='utc'/>

  <devices>
    <!-- Main disk -->
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/libvirt/images/ubuntu-22.04-server-cloudimg-amd64.img'/>
      <target dev='vda' bus='virtio'/>
    </disk>

    <!-- cloud-init seed ISO -->
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='/var/lib/libvirt/images/seed.iso'/>
      <target dev='vdb' bus='virtio'/>
      <readonly/>
    </disk>

    <!-- Network (user-mode NAT, like -netdev user) -->
    <interface type='user'>
      <model type='virtio'/>
    </interface>

    <!-- Graphics -->
    <graphics type='spice' autoport='yes'/>

    <!-- Video -->
    <video>
      <model type='virtio' heads='1'/>
    </video>

    <!-- Console -->
    <console type='pty'/>

    <!-- Input -->
    <input type='tablet' bus='usb'/>

    <!-- RNG -->
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
  </devices>
</domain>`, 4096)
}
