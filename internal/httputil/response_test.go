package httputil

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Verifies: STK-REQ-083, SYS-REQ-171, SW-REQ-158
// SW-REQ-158:nominal:nominal
// SW-REQ-158:boundary:nominal
// SW-REQ-158:determinism:nominal
func TestRequestUtilities(t *testing.T) {
	tests := []struct {
		name   string
		handle func(http.ResponseWriter, *http.Request)
		status int
	}{
		{name: "entity too large", handle: EntityTooLarge, status: http.StatusRequestEntityTooLarge},
		{name: "length required", handle: LengthRequired, status: http.StatusLengthRequired},
		{name: "internal server error", handle: InternalServerError, status: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tt.handle(w, nil)

			result := w.Result()
			defer result.Body.Close()

			body, err := io.ReadAll(result.Body)
			assert.NoError(t, err)
			assert.Equal(t, tt.status, result.StatusCode)
			assert.Contains(t, string(body), http.StatusText(tt.status))
		})
	}
}

// Verifies: STK-REQ-083, SYS-REQ-171, SW-REQ-158
// SW-REQ-158:nominal:nominal
// SW-REQ-158:boundary:nominal
// SW-REQ-158:determinism:nominal
func TestRemoveResponseTransferEncoding(t *testing.T) {
	tests := []struct {
		name           string
		response       *http.Response
		encoding       string
		expectedOutput []string
	}{
		{
			name: "Remove chunked encoding",
			response: &http.Response{
				TransferEncoding: []string{"chunked", "gzip"},
			},
			encoding:       "chunked",
			expectedOutput: []string{"gzip"},
		},
		{
			name: "Remove gzip encoding",
			response: &http.Response{
				TransferEncoding: []string{"chunked", "gzip"},
			},
			encoding:       "gzip",
			expectedOutput: []string{"chunked"},
		},
		{
			name: "Remove non-existent encoding",
			response: &http.Response{
				TransferEncoding: []string{"chunked", "gzip"},
			},
			encoding:       "deflate",
			expectedOutput: []string{"chunked", "gzip"},
		},
		{
			name: "Remove from empty slice",
			response: &http.Response{
				TransferEncoding: []string{},
			},
			encoding:       "gzip",
			expectedOutput: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			RemoveResponseTransferEncoding(tc.response, tc.encoding)
			assert.Equal(t, tc.expectedOutput, tc.response.TransferEncoding)
		})
	}
}
