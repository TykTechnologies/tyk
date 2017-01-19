package main

import (
	"github.com/justinas/alice"
)

func AppendMiddleware(chain *[]alice.Constructor, mw TykMiddlewareImplementation, tykMwSuper *TykMiddleware) {
	if mw.IsEnabledForSpec() {
		*chain = append(*chain, CreateMiddleware(mw, tykMwSuper))
	}
}

func CheckCBEnabled(tykMwSuper *TykMiddleware) bool {
	var used bool
	for _, version := range tykMwSuper.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.CircuitBreaker) > 0 {
			used = true
			tykMwSuper.Spec.CircuitBreakerEnabled = true
		}
	}

	return used
}

func CheckETEnabled(tykMwSuper *TykMiddleware) bool {
	var used bool
	for _, version := range tykMwSuper.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.HardTimeouts) > 0 {
			used = true
			tykMwSuper.Spec.EnforcedTimeoutEnabled = true
		}
	}

	return used
}
