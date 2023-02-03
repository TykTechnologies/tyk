package build

// These values are injected at build-time by CI/goreleaser.

var (
	// VERSION contains the tagged gateway version. It may contain a `rc` suffix,
	// which may be delimited with `-rc` or any other suffix. Follows Semver+Tag.
	VERSION = "v4.3.0"

	// BuiltBy contains the environment name from the build (goreleaser).
	BuiltBy string
	// BuildDate is the date the build was made at.
	BuildDate string
	// Commit is the commit hash for the build source.
	Commit string
)
