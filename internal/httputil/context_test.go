package httputil_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/internal/httputil"

	"github.com/TykTechnologies/tyk/internal/model"

	"github.com/stretchr/testify/assert"
)

func createReq(tb testing.TB) *http.Request {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", nil)
	assert.NoError(tb, err)
	return req
}

func TestUpstreamAuth(t *testing.T) {
	t.Run("valid auth provider", func(t *testing.T) {
		mockAuthProvider := &model.MockUpstreamAuthProvider{}
		req := createReq(t)

		httputil.SetUpstreamAuth(req, mockAuthProvider)

		// Retrieve the auth provider from the request's context to verify it was set
		retrievedAuth := httputil.GetUpstreamAuth(req)
		assert.NotNil(t, retrievedAuth)
		assert.Equal(t, mockAuthProvider, retrievedAuth)
	})

	t.Run("no auth provider", func(t *testing.T) {
		req := createReq(t)

		retrievedAuth := httputil.GetUpstreamAuth(req)
		assert.Nil(t, retrievedAuth)
	})

	t.Run("invalid auth provider", func(t *testing.T) {
		req := createReq(t)

		// Set a context with a value that is not of type proxy.UpstreamAuthProvider
		ctx := context.WithValue(req.Context(), httputil.ContextKey("upstream-auth"), "invalid-type")
		httputil.SetContext(req, ctx)

		retrievedAuth := httputil.GetUpstreamAuth(req)
		assert.Nil(t, retrievedAuth)
	})
}

func TestSetContext(t *testing.T) {
	t.Run("add key", func(t *testing.T) {
		req := createReq(t)

		// Create a new context with a key-value pair
		ctx := context.WithValue(context.Background(), httputil.ContextKey("key"), "value")

		// Call SetContext to update the request's context
		httputil.SetContext(req, ctx)

		// Verify that the request's context has been updated
		retrievedValue := req.Context().Value(httputil.ContextKey("key"))
		assert.Equal(t, "value", retrievedValue)
	})

	t.Run("override key", func(t *testing.T) {

		req := createReq(t)
		existingCtx := context.WithValue(context.Background(), httputil.ContextKey("existingKey"), "existingValue")
		req = req.WithContext(existingCtx)

		// Create a new context to override the existing context
		newCtx := context.WithValue(context.Background(), httputil.ContextKey("newKey"), "newValue")

		// Call SetContext to update the request's context with the new context
		httputil.SetContext(req, newCtx)

		assert.Nil(t, req.Context().Value(httputil.ContextKey("existingKey")))
		assert.Equal(t, "newValue", req.Context().Value(httputil.ContextKey("newKey")))
	})

	t.Run("empty context", func(t *testing.T) {
		req := createReq(t)

		emptyCtx := context.Background()

		httputil.SetContext(req, emptyCtx)

		assert.Equal(t, emptyCtx, req.Context())
	})
}
