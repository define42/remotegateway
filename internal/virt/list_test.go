package virt

import (
	"testing"

	"libvirt.org/go/libvirt"
)

func TestStartVM(t *testing.T) {
	conn, err := libvirt.NewConnect(libvirtURI())
	if err != nil {
		t.Fatalf("Failed to connect to libvirt: %v", err)
	}
	defer conn.Close()
}
