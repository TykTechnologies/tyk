package httputil_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/TykTechnologies/tyk/internal/httputil"
)

func TestLimitReader(t *testing.T) {
	loremIpsum := "Lorem Ipsum dolor sit amet"

	// Create a test request with a request body larger than the limit
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(loremIpsum))

	// Create a test response recorder
	w := httptest.NewRecorder()

	// Call the LimitReader function
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		LimitReader(r, 10)

		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			if errors.Is(err, ErrContentTooLong) {
				EntityTooLarge(w, r)
				return
			}
			t.Errorf("Failed to read request body: %v", err)
		}

		// Check if the body matches the expected value
		expectedBody := "Lorem Ipsu"
		assert.Equal(t, expectedBody, body)
	})
	handler.ServeHTTP(w, req)

	// Check the response status code
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Result().StatusCode)
}
