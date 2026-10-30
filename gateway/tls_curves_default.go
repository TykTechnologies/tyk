//go:build !fips

package gateway

import "crypto/tls"

// defaultCurvePreferences returns nil for standard builds, allowing the Go runtime's
// default curve negotiation order (prioritizing X25519MLKEM768 and X25519).
func defaultCurvePreferences() []tls.CurveID {
	return nil
}
