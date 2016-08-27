package main

import (
	"github.com/justinas/alice"
)

func AppendMiddleware(thisChain *[]alice.Constructor, thisMW TykMiddlewareImplementation, tykMwSuper *TykMiddleware) {
	if thisMW.IsEnabledForSpec() {
		*thisChain = append(*thisChain, CreateMiddleware(thisMW, tykMwSuper))
	}
}

func CheckCBEnabled(tykMwSuper *TykMiddleware) bool {
	var used bool
	for _, thisVersion := range tykMwSuper.Spec.VersionData.Versions {
		if len(thisVersion.ExtendedPaths.CircuitBreaker) > 0 {
			used = true
			tykMwSuper.Spec.CircuitBreakerEnabled = true
		}
	}

	return used
}

func CheckETEnabled(tykMwSuper *TykMiddleware) bool {
	var used bool
	for _, thisVersion := range tykMwSuper.Spec.VersionData.Versions {
		if len(thisVersion.ExtendedPaths.HardTimeouts) > 0 {
			used = true
			tykMwSuper.Spec.EnforcedTimeoutEnabled = true
		}
	}

	return used
}
