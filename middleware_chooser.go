package main

import (
	"github.com/justinas/alice"
)

func AppendMiddleware(chain *[]alice.Constructor, mw TykMiddlewareImplementation, tykMwSuper *TykMiddleware) {
	if mw.IsEnabledForSpec() {
		*chain = append(*chain, CreateMiddleware(mw, tykMwSuper))
	}
}

func CheckCBEnabled(tykMwSuper *TykMiddleware) (used bool) {
	for _, v := range tykMwSuper.Spec.VersionData.Versions {
		if len(v.ExtendedPaths.CircuitBreaker) > 0 {
			used = true
			tykMwSuper.Spec.CircuitBreakerEnabled = true
		}
	}
	return
}

func CheckETEnabled(tykMwSuper *TykMiddleware) (used bool) {
	for _, v := range tykMwSuper.Spec.VersionData.Versions {
		if len(v.ExtendedPaths.HardTimeouts) > 0 {
			used = true
			tykMwSuper.Spec.EnforcedTimeoutEnabled = true
		}
	}
	return
}
