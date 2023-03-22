package plugin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	plugin "github.com/TykTechnologies/tyk/pkg/plugin/c-archive"
)

func TestLoad(t *testing.T) {
	handlerFunc := plugin.Handler("plugin.so", "MyHandler")
	assert.NotNil(t, handlerFunc)

	req, err := http.NewRequest("GET", "http://httpbin.org", nil)
	assert.NoError(t, err)

	// Invoke the handler and assert the response
	responseRecorder := httptest.NewRecorder()
	handlerFunc(responseRecorder, req)
	assert.Equal(t, "OK", responseRecorder.Body.String())
}
