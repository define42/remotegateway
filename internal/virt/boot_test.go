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

	vmName, err := virt.BootNewVM(testVMName, user)
	if err != nil {
		t.Fatalf("Failed to boot new VM %s: %v", vmName, err)
	}

	vms, err := virt.ListVMs(testUsername)
	if err != nil {
		t.Fatalf("Failed to list VMs: %v", err)
	}

	// Verify that the VM is in the list
	found := false
	for _, v := range vms {
		if v.Name == vmName {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Booted VM %s not found in VM list", vmName)
	}
}
