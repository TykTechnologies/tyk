package httputil_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/internal/httputil"
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
			if errors.Is(err, http.ErrBodyNotAllowed) {
				httputil.EntityTooLarge(w, r)
				return
			}
			t.Errorf("Failed to read request body: %v", err)
		}

		// Check if the body matches the expected value
		expectedBody := "Lorem Ipsu"
		if string(body) != expectedBody {
			t.Errorf("Unexpected request body. Got: %s, want: %s", body, expectedBody)
		}
	})
	handler.ServeHTTP(w, req)

	// Check the response status code
	expectedStatusCode := http.StatusRequestEntityTooLarge
	if w.Result().StatusCode != expectedStatusCode {
		t.Errorf("Unexpected status code. Got: %d, want: %d", w.Result().StatusCode, expectedStatusCode)
	}
}
