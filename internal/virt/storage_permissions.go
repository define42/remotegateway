package virt

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const volumeModeEnv = "LIBVIRT_VOLUME_MODE"

func storageVolPermissionsXML() (string, error) {
	modeStr := strings.TrimSpace(os.Getenv(volumeModeEnv))
	if modeStr == "" {
		return "", nil
	}
	modeStr = strings.TrimPrefix(modeStr, "0o")
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return "", fmt.Errorf("invalid %s %q: %w", volumeModeEnv, modeStr, err)
	}
	return fmt.Sprintf("\n    <permissions>\n      <mode>%04o</mode>\n    </permissions>", mode), nil
}
