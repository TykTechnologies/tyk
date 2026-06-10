package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOriginalRequestPath(t *testing.T) {
	t.Run("round-trip set and get returns stored path", func(t *testing.T) {
		tests := []struct {
			name string
			path string
		}{
			{"simple path", "/api/v1/users"},
			{"URL-encoded path preserved", "/api/v1/users/Mar%C3%ADa%20Santos"},
			{"trailing slash preserved", "/api/v1/users/"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, "http://example.com"+tt.path, nil)
				ctxSetOriginalRequestPath(r, tt.path)
				got := ctxGetOriginalRequestPath(r)
				assert.Equal(t, tt.path, got)
			})
		}
	})

	t.Run("unset context returns empty string", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
		got := ctxGetOriginalRequestPath(r)
		assert.Equal(t, "", got)
	})
}
