//go:build fips

package gateway

import "crypto/tls"

// defaultCurvePreferences returns NIST-approved curves and post-quantum hybrids for FIPS mode.
// X25519 and X25519MLKEM768 are excluded as Curve25519 is unapproved under NIST SP 800-56A / SP 800-140C.
func defaultCurvePreferences() []tls.CurveID {
	return []tls.CurveID{
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}
}
