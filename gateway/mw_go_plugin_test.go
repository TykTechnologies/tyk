package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

// TestLoadPlugin test the function to load a middleware goplugin
// ToDo: find out how to successfully load a plugin for testing
func TestLoadPlugin(t *testing.T) {
	plugin := GoPluginMiddleware{
		Path: "/any-fake-path",
	}

	pluginLoaded := plugin.loadPlugin()
	assert.Equal(t, false, pluginLoaded)
}

func TestGoPluginMiddleware_EnabledForSpec(t *testing.T) {
	gpm := GoPluginMiddleware{
		BaseMiddleware: &BaseMiddleware{},
	}
	apiSpec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	gpm.Spec = apiSpec

	assert.False(t, gpm.EnabledForSpec())

	t.Run("global go plugin", func(t *testing.T) {
		gpm.Path = "plugin.so"
		gpm.SymbolName = "name"

		assert.True(t, gpm.EnabledForSpec())

		gpm.Path = ""
		gpm.SymbolName = ""
	})

	t.Run("per path go plugin", func(t *testing.T) {
		ep := apidef.ExtendedPathsSet{GoPlugin: make([]apidef.GoPluginMeta, 1)}
		apiSpec.VersionData.Versions = map[string]apidef.VersionInfo{"v1": {
			ExtendedPaths: ep,
		}}

		assert.True(t, gpm.EnabledForSpec())

		t.Run("disabled", func(t *testing.T) {
			ep.GoPlugin[0].Disabled = true

			assert.False(t, gpm.EnabledForSpec())
		})
	})
}

func TestGoPluginMiddleware_handleErrorResponseLogLevel(t *testing.T) {
	logger, hook := test.NewNullLogger()
	entry := logrus.NewEntry(logger)

	m := &GoPluginMiddleware{BaseMiddleware: &BaseMiddleware{}}

	tests := []struct {
		name          string
		statusCode    int
		expectedLevel logrus.Level
	}{
		{"request timeout logs at warn", http.StatusRequestTimeout, logrus.WarnLevel},
		{"teapot logs at warn", http.StatusTeapot, logrus.WarnLevel},
		{"rate limit logs at warn", http.StatusTooManyRequests, logrus.WarnLevel},
		{"service unavailable logs at warn", http.StatusServiceUnavailable, logrus.WarnLevel},
		{"bad request logs at error", http.StatusBadRequest, logrus.ErrorLevel},
		{"unauthorized logs at error", http.StatusUnauthorized, logrus.ErrorLevel},
		{"internal server error logs at error", http.StatusInternalServerError, logrus.ErrorLevel},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hook.Reset()

			r := httptest.NewRequest(http.MethodGet, "/test", nil)
			rw := &customResponseWriter{
				ResponseWriter: httptest.NewRecorder(),
				responseSent:   true,
				statusCodeSent: tc.statusCode,
			}

			err, code := m.handleErrorResponse(r, rw, entry)

			assert.ErrorIs(t, err, ErrResponseErrorSent)
			assert.Equal(t, tc.statusCode, code)

			if assert.Len(t, hook.Entries, 1) {
				assert.Equal(t, tc.expectedLevel, hook.LastEntry().Level)
				assert.Equal(t, "Failed to process request with Go-plugin middleware func", hook.LastEntry().Message)
			}
		})
	}

	// 403 is not in the table because handleErrorResponse fires
	// EventAuthFailure for it, which needs the full test framework; assert
	// its mapping directly on the pure function instead.
	assert.Equal(t, logrus.ErrorLevel, levelForPluginStatus(http.StatusForbidden))
}
