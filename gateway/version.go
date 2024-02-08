package gateway

import (
	"github.com/TykTechnologies/tyk/internal/build"
)

// Deprecated: All of the following variables are deprecated in favor of
// importing the information from the internal/build package directly.
// These placeholders remain for compatibility but are likely to be
// removed in a future version.
var (
	VERSION = build.Version
	Commit  = build.Commit
)
