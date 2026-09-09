//go:build !ee && !dev

package gateway

// oauth2BuildIsEE reports whether the current build includes the
// EE-only RFC 8693 token exchange runtime. Used by the EE/OSS gating
// regression tests to skip OSS-only or EE-only scenarios.
const oauth2BuildIsEE = false
