package plugin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/pkg/plugin"
)

func TestPluginRegister(t *testing.T) {
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("OK"))
		assert.NoError(t, err)
	}

	// Registry miss
	assert.Nil(t, plugin.Handler("internal", "test"))

	// Register handler, retrieve it
	plugin.RegisterHandler("internal", "test", testHandler)
	gotHandler := plugin.Handler("internal", "test")
	assert.NotNil(t, gotHandler)

	// Invoke the handler and assert the response
	responseRecorder := httptest.NewRecorder()
	gotHandler(responseRecorder, nil)
	assert.Equal(t, "OK", responseRecorder.Body.String())
}
