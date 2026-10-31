package pathnormalizer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/pathnormalizer"
)

// FuzzParser drives the parser with arbitrary paths. Paths reach it straight
// from user-authored API definitions, so no input may fault it, however
// malformed. A path it accepts also has to be stable: feeding the normalized
// form back in must yield that same form, since the conversion looks endpoints
// up by it.
func FuzzParser(f *testing.F) {
	for _, seed := range []string{
		"",
		"/",
		"//",
		"/user/[0-9]+",
		"/user/{id}",
		"/user/{id:[0-9]+}",
		"/users/{[0-9]{3}}/",
		"/user/id:[0-9]+/accelerate",
		"/v1.Service/stats.Service",
		"/user/[a-zA-Z]+/account/[0-9]+",
		"/{",
		"/user/{",
		"/abc}",
		"/users/{aaa[0-9]{2}/}",
		"/users/{[0-9]{2}}[0-9]{2}",
		"/{customRegex1}",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, path string) {
		normalized, err := pathnormalizer.NewParser().Parse(path)

		if err != nil {
			return
		}

		require.NotNil(t, normalized)

		again, err := pathnormalizer.NewParser().Parse("/" + normalized.RawOpIdPrefix())
		require.NoError(t, err, "normalized form of %q was rejected on the way back in", path)
		assert.Equal(t, normalized.RawOpIdPrefix(), again.RawOpIdPrefix(),
			"normalizing %q is not stable", path)
	})
}
