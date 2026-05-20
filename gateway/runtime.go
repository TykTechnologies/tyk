package gateway

import (
	"os"
	"strings"

	"go.uber.org/automaxprocs/maxprocs"
)

// configureAutoMaxProcs aligns GOMAXPROCS with the container's cgroup CPU
// quota. Default-on; disable via TYK_GW_AUTOMAXPROCS=0/false/no/off/disabled.
// No-op outside cgroup-quota environments.
func configureAutoMaxProcs() {
	if !autoMaxProcsEnabled() {
		return
	}
	if _, err := maxprocs.Set(maxprocs.Logger(mainLog.Infof)); err != nil {
		mainLog.WithError(err).Warn("automaxprocs: failed to set GOMAXPROCS")
	}
}

func autoMaxProcsEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TYK_GW_AUTOMAXPROCS"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}
