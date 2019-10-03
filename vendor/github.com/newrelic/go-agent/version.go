package newrelic

import "github.com/newrelic/go-agent/internal"

const (
	major = "2"
	minor = "13"
	patch = "0"

	// Version is the full string version of this Go Agent.
	Version = major + "." + minor + "." + patch
)

func init() { internal.TrackUsage("Go", "Version", Version) }
