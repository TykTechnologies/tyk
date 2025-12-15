package paramextractor_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/paramextractor"
)

// Helper function to create an HTTP request with a specific path
func createRequest(t *testing.T, path string) string {
	t.Helper()
	urlInstance, err := url.Parse("http://example.com" + path)
	assert.NoError(t, err)
	return urlInstance.Path
}

// TestStrictExtractor tests the strict path matching extractor
func TestStrictExtractor(t *testing.T) {
	extractor := paramextractor.NewParamExtractorFromFlags(false, false) // Creates a strict extractor

	t.Run("ExactMatchWithSingleParameter", func(t *testing.T) {
		req := createRequest(t, "/users/123")

		params, err := extractor.Extract(req, "/users/{id}")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"id": "123"}, params)
	})

	t.Run("ExactMatchWithMultipleParameters", func(t *testing.T) {
		req := createRequest(t, "/users/123/posts/456")

		params, err := extractor.Extract(req, "/users/{userId}/posts/{postId}")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"userId": "123", "postId": "456"}, params)
	})

	t.Run("NoParameters", func(t *testing.T) {
		req := createRequest(t, "/users/all")

		params, err := extractor.Extract(req, "/users/all")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{}, params)
	})

	t.Run("DifferentSegmentCount", func(t *testing.T) {
		req := createRequest(t, "/users/123/profile")

		_, err := extractor.Extract(req, "/users/{id}")

		assert.Error(t, err)
	})

	t.Run("SegmentMismatch", func(t *testing.T) {
		req := createRequest(t, "/users/123")

		_, err := extractor.Extract(req, "/posts/{id}")

		assert.Error(t, err)
	})

	t.Run("TrailingSlashInRequest", func(t *testing.T) {
		req := createRequest(t, "/users/123/")

		params, err := extractor.Extract(req, "/users/{id}")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"id": "123"}, params)
	})

	t.Run("TrailingSlashInPattern", func(t *testing.T) {
		req := createRequest(t, "/users/123")

		params, err := extractor.Extract(req, "/users/{id}/")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"id": "123"}, params)
	})

	t.Run("EmptyPathSegments", func(t *testing.T) {
		req := createRequest(t, "/users//posts")

		params, err := extractor.Extract(req, "/users/{id}/posts")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"id": ""}, params)
	})
}

// TestPrefixExtractor tests the prefix path matching extractor
func TestPrefixExtractor(t *testing.T) {
	extractor := paramextractor.NewParamExtractorFromFlags(true, false) // Creates a prefix extractor

	t.Run("ExactMatch", func(t *testing.T) {
		req := createRequest(t, "/api/users/123")

		params, err := extractor.Extract(req, "/api/users/{id}")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"id": "123"}, params)
	})

	t.Run("PrefixMatchWithAdditionalSegments", func(t *testing.T) {
		req := createRequest(t, "/api/users/123/profile/edit")

		params, err := extractor.Extract(req, "/api/users/{id}")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"id": "123"}, params)
	})

	t.Run("MultipleParameters", func(t *testing.T) {
		req := createRequest(t, "/api/users/123/posts/456/comments")

		params, err := extractor.Extract(req, "/api/users/{userId}/posts/{postId}")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"userId": "123", "postId": "456"}, params)
	})

	t.Run("NotEnoughSegmentsInRequest", func(t *testing.T) {
		req := createRequest(t, "/api/users")

		_, err := extractor.Extract(req, "/api/users/{id}")

		assert.Error(t, err)
	})

	t.Run("SegmentMismatch", func(t *testing.T) {
		req := createRequest(t, "/api/posts/123")

		_, err := extractor.Extract(req, "/api/users/{id}")

		assert.Error(t, err)
	})
}

// TestSuffixExtractor tests the suffix path matching extractor
func TestSuffixExtractor(t *testing.T) {
	extractor := paramextractor.NewParamExtractorFromFlags(false, true) // Creates a suffix extractor

	t.Run("ExactMatch", func(t *testing.T) {
		req := createRequest(t, "/users/123/profile")

		params, err := extractor.Extract(req, "/users/{id}/profile")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"id": "123"}, params)
	})

	t.Run("SuffixMatchWithAdditionalPrefixSegments", func(t *testing.T) {
		req := createRequest(t, "/api/v1/users/123/profile")

		params, err := extractor.Extract(req, "/users/{id}/profile")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"id": "123"}, params)
	})

	t.Run("MultipleParameters", func(t *testing.T) {
		req := createRequest(t, "/api/users/123/posts/456")

		params, err := extractor.Extract(req, "/users/{userId}/posts/{postId}")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"userId": "123", "postId": "456"}, params)
	})

	t.Run("NotEnoughSegmentsInRequest", func(t *testing.T) {
		req := createRequest(t, "/profile")

		_, err := extractor.Extract(req, "/users/{id}/profile")

		assert.Error(t, err)
	})

	t.Run("SegmentMismatch", func(t *testing.T) {
		req := createRequest(t, "/api/users/123/settings")

		_, err := extractor.Extract(req, "/users/{id}/profile")

		assert.Error(t, err)
	})
}

// TestGlobExtractor tests the glob pattern matching extractor
func TestGlobExtractor(t *testing.T) {
	extractor := paramextractor.NewParamExtractorFromFlags(true, true) // Creates a glob extractor

	t.Run("SimpleParameterExtraction", func(t *testing.T) {
		req := createRequest(t, "/users/123")

		params, err := extractor.Extract(req, "/users/{id}")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"id": "123"}, params)
	})

	t.Run("MultipleParameters", func(t *testing.T) {
		req := createRequest(t, "/api/users/123/posts/456")

		params, err := extractor.Extract(req, "/api/users/{userId}/posts/{postId}")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"userId": "123", "postId": "456"}, params)
	})

	t.Run("NoMatch", func(t *testing.T) {
		req := createRequest(t, "/api/users/123")

		_, err := extractor.Extract(req, "/api/posts/{id}")

		assert.Error(t, err)
	})

	t.Run("InvalidPattern", func(t *testing.T) {
		req := createRequest(t, "/users/123")

		_, err := extractor.Extract(req, "/users/{id") // Missing closing brace

		assert.Error(t, err)
	})
}

// TestNewParamExtractorFromFlags tests the flag-based factory function
func TestNewParamExtractorFromFlags(t *testing.T) {
	t.Run("NoFlags", func(t *testing.T) {
		extractor := paramextractor.NewParamExtractorFromFlags(false, false)

		// Test behavior to verify it's a strict extractor
		req := createRequest(t, "/users/123/profile")
		_, err := extractor.Extract(req, "/users/{id}")
		assert.Error(t, err, "Strict extractor should fail with different segment count")

		req = createRequest(t, "/users/123")
		params, err := extractor.Extract(req, "/users/{id}")
		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"id": "123"}, params)
	})

	t.Run("PrefixOnly", func(t *testing.T) {
		extractor := paramextractor.NewParamExtractorFromFlags(true, false)

		// Test behavior to verify it's a prefix extractor
		req := createRequest(t, "/api/users/123/profile")
		params, err := extractor.Extract(req, "/api/users/{id}")
		assert.NoError(t, err, "Prefix extractor should match with additional segments")
		assert.Equal(t, map[string]string{"id": "123"}, params)
	})

	t.Run("SuffixOnly", func(t *testing.T) {
		extractor := paramextractor.NewParamExtractorFromFlags(false, true)

		// Test behavior to verify it's a suffix extractor
		req := createRequest(t, "/api/v1/users/123/profile")
		params, err := extractor.Extract(req, "/users/{id}/profile")
		assert.NoError(t, err, "Suffix extractor should match with additional prefix segments")
		assert.Equal(t, map[string]string{"id": "123"}, params)
	})

	t.Run("BothFlags", func(t *testing.T) {
		extractor := paramextractor.NewParamExtractorFromFlags(true, true)

		// Test behavior to verify it's a glob extractor
		req := createRequest(t, "/api/users/123")
		params, err := extractor.Extract(req, "/api/users/{id}")
		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"id": "123"}, params)
	})
}

// TestEdgeCases tests various edge cases for all extractors
func TestEdgeCases(t *testing.T) {
	t.Run("EmptyPathAndPattern", func(t *testing.T) {
		// Test with strict extractor
		strictExtractor := paramextractor.NewParamExtractorFromFlags(false, false)
		req := createRequest(t, "")

		params, err := strictExtractor.Extract(req, "")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{}, params)

		// Test with prefix extractor
		prefixExtractor := paramextractor.NewParamExtractorFromFlags(true, false)
		params, err = prefixExtractor.Extract(req, "")

		assert.NoError(t, err)
		assert.Equal(t, map[string]string{}, params)
	})
}
