package seediso_test

import (
	"os"
	"path"
	"remotegateway/internal/seediso"
	"testing"
)

func TestCcreateUbuntuSeedISO(t *testing.T) {
	isoPath := path.Join(t.TempDir(), "test-ubuntu-seed.iso")

	err := seediso.CreateUbuntuSeedISO(isoPath)
	if err != nil {
		t.Fatalf("Failed to create Ubuntu seed ISO: %v", err)
	}

	info, err := os.Stat(isoPath)
	if err != nil {
		t.Fatalf("Failed to stat created ISO: %v", err)
	}

	if info.Size() == 0 {
		t.Fatalf("Created ISO is empty")
	}
}
