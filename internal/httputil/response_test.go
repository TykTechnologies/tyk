package httputil

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestUtilities(t *testing.T) {
	w := httptest.NewRecorder()
	EntityTooLarge(w, nil)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Result().StatusCode)

	w = httptest.NewRecorder()
	LengthRequired(w, nil)
	assert.Equal(t, http.StatusLengthRequired, w.Result().StatusCode)

	w = httptest.NewRecorder()
	InternalServerError(w, nil)
	assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
}

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
