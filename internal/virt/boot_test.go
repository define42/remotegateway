package virt_test

import (
	"log"
	"remotegateway/internal/seediso"
	"remotegateway/internal/virt"
	"testing"

	"libvirt.org/go/libvirt"
)

func TestStartVM(t *testing.T) {
	conn, err := libvirt.NewConnect(virt.LibvirtURI())
	if err != nil {
		t.Fatalf("Failed to connect to libvirt: %v", err)
	}
	defer conn.Close()

	volumeName := "test"

	if err := virt.DestroyExistingDomain(conn, volumeName); err != nil {
		t.Fatalf("Failed to destroy existing domain: %v", err)
	}

	pool, err := conn.LookupStoragePoolByName("default")
	if err != nil {
		t.Fatalf("Failed to lookup storage pool: %v", err)
	}
	defer func() {
		if err := pool.Free(); err != nil {
			t.Fatalf("Failed to free storage pool: %v", err)
		}
	}()

	vol, err := pool.LookupStorageVolByName(volumeName)
	if err == nil {
		defer func() {
			_ = vol.Free()
		}()
		log.Printf("Volume %s exists", volumeName)
		if err := vol.Delete(0); err != nil {
			t.Fatalf("Failed to delete existing volume: %v", err)
		}
		log.Printf("Deleted volume %s", volumeName)
	}

	vol, err = pool.LookupStorageVolByName("seed.iso")
	if err == nil {
		defer func() {
			_ = vol.Free()
		}()
		log.Printf("Volume %s exists", volumeName)
		if err := vol.Delete(0); err != nil {
			t.Fatalf("Failed to delete existing volume: %v", err)
		}
		log.Printf("Deleted volume %s", volumeName)
	}

	if err := virt.CopyAndResizeVolume(conn, "default", volumeName, "noble-server-cloudimg-amd64.img", 40*1024*1024*1024); err != nil {
		t.Fatalf("Failed to copy and resize volume: %v", err)
	}

	if err := seediso.CreateUbuntuSeedISOToPool(conn, "default", "seed.iso", "test", "password", "testhost"); err != nil {
		t.Fatalf("Failed to create seed ISO: %v", err)
	}

	if err := virt.StartVM(volumeName); err != nil {
		t.Fatalf("Failed to start VM: %v", err)
	}

}
