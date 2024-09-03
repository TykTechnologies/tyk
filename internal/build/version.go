package build

import (
	"regexp"
)

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

// versionRe matches a minimal semver, `v0.0.0`, where 0 may be any number.
var versionRe = regexp.MustCompile(`^v\d+\.\d+\.\d+`)

// CleanVersion returns a sanitized gateway version. If the version
// doesn't match the semver regex, it will return the original string.
func CleanVersion(version string) string {
	// Find the first match of the regex in the version string
	match := versionRe.FindString(version)
	if match != "" {
		return match
	}
	// Return as-is otherwise
	return version
}
