package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
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

type mockAuthEventHandler struct {
	eventChan chan config.EventMessage
}

func (m *mockAuthEventHandler) Init(interface{}) error {
	return nil
}

func (m *mockAuthEventHandler) HandleEvent(e config.EventMessage) {
	m.eventChan <- e
}

func TestGoPluginMiddleware_HandleErrorResponse(t *testing.T) {
	tests := []struct {
		name              string
		statusCode        int
		expectAuthFailure bool
	}{
		{
			name:              "HTTP 401 Unauthorized fires EventAuthFailure",
			statusCode:        http.StatusUnauthorized,
			expectAuthFailure: true,
		},
		{
			name:              "HTTP 403 Forbidden fires EventAuthFailure",
			statusCode:        http.StatusForbidden,
			expectAuthFailure: true,
		},
		{
			name:              "HTTP 400 Bad Request does not fire EventAuthFailure",
			statusCode:        http.StatusBadRequest,
			expectAuthFailure: false,
		},
		{
			name:              "HTTP 500 Internal Server Error does not fire EventAuthFailure",
			statusCode:        http.StatusInternalServerError,
			expectAuthFailure: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eventChan := make(chan config.EventMessage, 1)
			mockHandler := &mockAuthEventHandler{eventChan: eventChan}

			spec := &APISpec{
				APIDefinition: &apidef.APIDefinition{},
				EventPaths: map[apidef.TykEvent][]config.TykEventHandler{
					EventAuthFailure: {mockHandler},
				},
			}

			mw := &GoPluginMiddleware{
				BaseMiddleware: &BaseMiddleware{
					Spec: spec,
				},
			}

			rec := httptest.NewRecorder()
			rw := &customResponseWriter{ResponseWriter: rec}
			rw.WriteHeader(tc.statusCode)
			_, err := rw.Write([]byte("error response"))
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "/test/path", nil)
			logger := logrus.NewEntry(logrus.New())

			returnedErr, code := mw.handleErrorResponse(req, rw, logger)

			assert.Equal(t, tc.statusCode, code)
			assert.ErrorIs(t, returnedErr, ErrResponseErrorSent)

			if tc.expectAuthFailure {
				select {
				case ev := <-eventChan:
					assert.Equal(t, EventAuthFailure, ev.Type)
					meta, ok := ev.Meta.(EventKeyFailureMeta)
					require.True(t, ok)
					assert.Equal(t, "Auth Failure", meta.Message)
					assert.Equal(t, "/test/path", meta.Path)
				case <-time.After(100 * time.Millisecond):
					t.Fatal("expected EventAuthFailure to be fired, but timed out")
				}
			} else {
				select {
				case ev := <-eventChan:
					t.Fatalf("unexpected event fired: %v", ev.Type)
				case <-time.After(50 * time.Millisecond):
					// Expected: No event fired
				}
			}
		})
	}
}
