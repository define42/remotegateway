package virt_test

import (
	typesUser "remotegateway/internal/types"
	"remotegateway/internal/virt"
	"testing"
)

const (
	testVMName   = "test-vm"
	testUsername = "testuser"
	testPassword = "dogood"
)

func TestStartVM(t *testing.T) {

	user, err := typesUser.NewUser(testUsername, testPassword, "")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	if err := virt.BootNewVM(testVMName, user); err != nil {
		t.Fatalf("Failed to boot new VM: %v", err)
	}

	vms, err := virt.ListVMs(testUsername)
	if err != nil {
		t.Fatalf("Failed to list VMs: %v", err)
	}

	if len(vms) != 1 {
		t.Fatalf("Expected 1 VM, got %d", len(vms))
	}

	t.Logf("VMs: %+v", vms)

}
