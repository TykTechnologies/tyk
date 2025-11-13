package build

// These values are injected at build-time from CI.
var (
	// Version contains the tagged gateway version. It may contain a `rc` suffix,
	// which may be delimited with `-rc` or any other suffix. Follows Semver+Tag.
	Version = "v5.5.0-dev"

	// BuiltBy contains the environment name from the build (goreleaser).
	BuiltBy string = "dev"

	// BuildDate is the date the build was made at.
	BuildDate string

	// Commit is the commit hash for the build source.
	Commit string
)
