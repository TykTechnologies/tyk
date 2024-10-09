package gateway_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestResponseGoPluginMiddlewareInit(t *testing.T) {
	plugin := ResponseGoPluginMiddleware{
		Path: "/any-fake-path",
	}

	middlewareDefinition := apidef.MiddlewareDefinition{
		Path: "any-path",
		Name: "fake middleware definition name",
	}
	err := plugin.Init(middlewareDefinition, &APISpec{})

	assert.Error(t, err)
}

func TestResponseGoPluginMiddlewareBase(t *testing.T) {
	// Initialize the ResponseGoPluginMiddleware
	h := &ResponseGoPluginMiddleware{
		BaseTykResponseHandler: BaseTykResponseHandler{},
	}

	// Get the base using the method
	base := h.Base()

	// Check that the returned base is indeed the BaseTykResponseHandler of h
	require.Equal(t, &h.BaseTykResponseHandler, base, "Base method did not return the expected BaseTykResponseHandler")
}

func TestResponseGoPluginMiddlewareName(t *testing.T) {
	// Initialize the ResponseGoPluginMiddleware
	h := &ResponseGoPluginMiddleware{}

	// Get the name using the method
	name := h.Name()

	// Check that the returned name is "ResponseGoPluginMiddleware"
	require.Equal(t, "ResponseGoPluginMiddleware", name, "Name method did not return the expected value")
}
