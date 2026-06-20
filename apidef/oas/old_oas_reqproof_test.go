package oas

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: SYS-REQ-104, SW-REQ-056
// SW-REQ-056:nominal:nominal
// SW-REQ-056:boundary:nominal
// SW-REQ-056:error_handling:nominal
// SW-REQ-056:error_handling:negative
func TestOldOASConversionPreservesDocumentShape(t *testing.T) {
	t.Run("valid deprecated wrapper converts to newer OAS wrapper", func(t *testing.T) {
		old := &OldOAS{
			T: openapi3.T{
				OpenAPI: DefaultOpenAPI,
				Info: &openapi3.Info{
					Title:       "legacy",
					Description: "deprecated wrapper",
					Version:     "1.2.3",
				},
				Paths: openapi3.NewPaths(),
			},
		}

		got, err := old.ConvertToNewerOAS()

		require.NoError(t, err)
		require.NotNil(t, got)
		require.NotNil(t, got.Info)
		assert.Equal(t, DefaultOpenAPI, got.OpenAPI)
		assert.Equal(t, "legacy", got.Info.Title)
		assert.Equal(t, "deprecated wrapper", got.Info.Description)
		assert.Equal(t, "1.2.3", got.Info.Version)
		assert.NotNil(t, got.Paths)
	})

	t.Run("unserializable deprecated wrapper returns error without converted OAS", func(t *testing.T) {
		old := &OldOAS{
			T: openapi3.T{
				OpenAPI: DefaultOpenAPI,
				Info:    &openapi3.Info{Title: "bad extension", Version: "1.0.0"},
				Paths:   openapi3.NewPaths(),
				Extensions: map[string]interface{}{
					"x-unserializable": make(chan int),
				},
			},
		}

		got, err := old.ConvertToNewerOAS()

		require.Error(t, err)
		assert.Nil(t, got)
	})
}
