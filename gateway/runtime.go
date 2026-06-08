package gateway

import (
	"go.uber.org/automaxprocs/maxprocs"
)

// configureAutoMaxProcs aligns GOMAXPROCS with the container's cgroup CPU
// quota. Default-on; pass disable=true to opt out (typically via the
// `disable_auto_max_procs` config field). No-op outside cgroup-quota
// environments.
func configureAutoMaxProcs(disable bool) {
	if disable {
		return
	}
	if _, err := maxprocs.Set(maxprocs.Logger(mainLog.Infof)); err != nil {
		mainLog.WithError(err).Warn("automaxprocs: failed to set GOMAXPROCS")
	}
}
