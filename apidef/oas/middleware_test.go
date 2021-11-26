package oas

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
)

func TestMiddleware(t *testing.T) {
	var emptyMiddleware Middleware

	var convertedAPI apidef.APIDefinition
	emptyMiddleware.ExtractTo(&convertedAPI)

	var resultMiddleware Middleware
	resultMiddleware.Fill(convertedAPI)

	assert.Equal(t, emptyMiddleware, resultMiddleware)
}

func TestGlobal(t *testing.T) {
	var emptyGlobal Global

	var convertedAPI apidef.APIDefinition
	emptyGlobal.ExtractTo(&convertedAPI)

	var resultGlobal Global
	resultGlobal.Fill(convertedAPI)

	assert.Equal(t, emptyGlobal, resultGlobal)
}

func TestCORS(t *testing.T) {
	var emptyCORS CORS

	var convertedCORS apidef.CORSConfig
	emptyCORS.ExtractTo(&convertedCORS)

	var resultCORS CORS
	resultCORS.Fill(convertedCORS)

	assert.Equal(t, emptyCORS, resultCORS)
}

func TestCache(t *testing.T) {
	var emptyCache Cache

	var convertedCache apidef.CacheOptions
	emptyCache.ExtractTo(&convertedCache)

	var resultCache Cache
	resultCache.Fill(convertedCache)

	assert.Equal(t, emptyCache, resultCache)
}

func TestExtendedPaths(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		paths := make(Paths)

		var convertedEP apidef.ExtendedPathsSet
		paths.ExtractTo(&convertedEP)

		resultPaths := make(Paths)
		resultPaths.Fill(convertedEP)

		assert.Equal(t, paths, resultPaths)
	})

	t.Run("filled", func(t *testing.T) {
		paths := make(Paths)
		Fill(t, &paths, 0)

		var convertedEP apidef.ExtendedPathsSet
		paths.ExtractTo(&convertedEP)

		resultPaths := make(Paths)
		resultPaths.Fill(convertedEP)

		assert.Equal(t, paths, resultPaths)
	})
}
