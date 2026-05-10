// Package oauth2common holds the pure-function helpers used by the
// gateway-side oauth2 security scheme to read and reason about JWT
// claims without depending on gateway concrete types.
//
// The package depends only on apidef/oas, the JWT library, and the
// standard library. The dependency arrow flows one direction:
// gateway/ depends on oauth2common, never the reverse.
package oauth2common
