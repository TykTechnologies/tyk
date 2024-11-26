package streamshadow

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

func TestMiddleware_Name(t *testing.T) {
	mw := &Middleware{}
	assert.Equal(t, "StreamShadowResponseMiddleware", mw.Name())
}

func TestMiddleware_Init(t *testing.T) {
	mw := &Middleware{}
	spec := &apidef.APISpec{}

	err := mw.Init(nil, spec)
	assert.NoError(t, err)
	assert.Equal(t, spec, mw.Spec)
	assert.NotNil(t, mw.logger)
}

func TestMiddleware_HandleResponse(t *testing.T) {
	// Create a logger that writes to a buffer
	var logBuffer bytes.Buffer
	logger := logrus.New()
	logger.Out = &logBuffer

	mw := &Middleware{
		logger: logger.WithField("mw", "StreamShadowResponseMiddleware"),
	}

	tests := []struct {
		name           string
		requestBody    string
		responseBody   string
		expectRequest  bool
		expectResponse bool
	}{
		{
			name:           "Valid JSON request and response",
			requestBody:    `{"name": "test"}`,
			responseBody:   `{"status": "ok"}`,
			expectRequest:  true,
			expectResponse: true,
		},
		{
			name:           "Invalid JSON request",
			requestBody:    `{"name": invalid}`,
			responseBody:   `{"status": "ok"}`,
			expectRequest:  false,
			expectResponse: true,
		},
		{
			name:           "Invalid JSON response",
			requestBody:    `{"name": "test"}`,
			responseBody:   `{"status": invalid}`,
			expectRequest:  true,
			expectResponse: false,
		},
		{
			name:           "Empty request and response",
			requestBody:    "",
			responseBody:   "",
			expectRequest:  false,
			expectResponse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset log buffer
			logBuffer.Reset()

			// Create request with body
			req := &http.Request{
				Body: io.NopCloser(strings.NewReader(tt.requestBody)),
			}

			// Create response with body
			res := &http.Response{
				Body: io.NopCloser(strings.NewReader(tt.responseBody)),
			}

			// Call HandleResponse
			err := mw.HandleResponse(nil, res, req, nil)
			assert.NoError(t, err)

			// Check if request payload was logged
			if tt.expectRequest {
				assert.Contains(t, logBuffer.String(), "Request payload")
				assert.Contains(t, logBuffer.String(), tt.requestBody)
			}

			// Check if response payload was logged
			if tt.expectResponse {
				assert.Contains(t, logBuffer.String(), "Response payload")
				assert.Contains(t, logBuffer.String(), tt.responseBody)
			}

			// Verify that bodies are still readable
			if tt.requestBody != "" {
				body, err := io.ReadAll(req.Body)
				assert.NoError(t, err)
				assert.Equal(t, tt.requestBody, string(body))
			}

			if tt.responseBody != "" {
				body, err := io.ReadAll(res.Body)
				assert.NoError(t, err)
				assert.Equal(t, tt.responseBody, string(body))
			}
		})
	}
}

func TestMiddleware_HandleError(t *testing.T) {
	mw := &Middleware{}
	// HandleError is a noop, so just verify it doesn't panic
	mw.HandleError(nil, nil)
}

func TestMiddleware_Enabled(t *testing.T) {
	mw := &Middleware{}
	assert.True(t, mw.Enabled())
}

func TestMiddleware_Base(t *testing.T) {
	mw := &Middleware{}
	assert.Equal(t, &mw.BaseTykResponseHandler, mw.Base())
}
