// The flags package is intended to hold compile-time flags.
package flags

// Flags are simple boolean values. For a flag that should
// be enabled for development but not for release, use
// the value `isDevelopment`.
//
// To enable development mode provide a `dev` tag to go test or build.
// By default, CI tests (go test) should always be run in dev mode.

const (
	// Rate limiter flags.
	EnableLeakyBucketRateLimiter   bool = true
	EnableTokenBucketRateLimiter   bool = isDevelopment
	EnableFixedWindowRateLimiter   bool = isDevelopment
	EnableSlidingWindowRateLimiter bool = isDevelopment
)
