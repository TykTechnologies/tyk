package adapter

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertApiDefinitionHeadersToHttpHeaders(t *testing.T) {
	t.Run("should return nil for empty input", func(t *testing.T) {
		assert.Nil(t, convertApiDefinitionHeadersToHttpHeaders(nil))
	})

	t.Run("should successfully convert API Definition header to Http Headers", func(t *testing.T) {
		apiDefinitionHeaders := map[string]string{
			"Authorization": "token",
			"X-Tyk-Key":     "value",
		}

		expectedHttpHeaders := http.Header{
			"Authorization": {"token"},
			"X-Tyk-Key":     {"value"},
		}

		actualHttpHeaders := convertApiDefinitionHeadersToHttpHeaders(apiDefinitionHeaders)
		assert.Equal(t, expectedHttpHeaders, actualHttpHeaders)
	})
}
