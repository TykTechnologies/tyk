package gateway

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
	"testing"
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
