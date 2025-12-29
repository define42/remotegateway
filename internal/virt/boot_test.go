package virt_test

import (
	"remotegateway/internal/virt"
	"testing"
)

func TestStartVM(t *testing.T) {

	vmName := "test-vm"
	username := "testuser"
	password := "testpassword"

	if err := virt.BootNewVM(vmName, username, password); err != nil {
		t.Fatalf("Failed to boot new VM: %v", err)
	}
}
