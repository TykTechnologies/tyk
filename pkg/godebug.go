package pkg

import (
	"fmt"
	"os"
)

const (
	goDebugEnvKey           = "GODEBUG"
	disableIgnoreCNDebugVal = "x509ignoreCN=0"
)

// SetGODebugEnv sets GODEBUG variable disable ignoreCN in x509 certs
func SetGODebugEnv() {
	existingGoDebug := os.Getenv(goDebugEnvKey)
	if existingGoDebug == "" {
		os.Setenv(goDebugEnvKey, disableIgnoreCNDebugVal)
	} else {
		os.Setenv(goDebugEnvKey, fmt.Sprintf("%s,%s", existingGoDebug, disableIgnoreCNDebugVal))
	}
}
