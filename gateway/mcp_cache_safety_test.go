package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

type cacheReadCountingStore struct {
	*storage.DummyStorage
	getCalls int
}

func (s *cacheReadCountingStore) GetKey(key string) (string, error) {
	s.getCalls++
	return s.DummyStorage.GetKey(key)
}

func TestRedisCacheMiddleware_BypassesCredentialSpecificMCPFiltering(t *testing.T) {
	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "mcp-api"
		spec.MarkAsMCP()
		spec.CacheOptions.EnableCache = true
	})[0]
	store := &cacheReadCountingStore{DummyStorage: storage.NewDummyStorage()}
	middleware := &RedisCacheMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}, store: store}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{Method: mcp.MethodToolsList})
	setSessionForTest(req, &user.SessionState{AccessRights: map[string]user.AccessDefinition{
		spec.APIID: {
			APIID: spec.APIID,
			MCPAccessRights: user.MCPAccessRights{
				Tools: user.AccessControlRules{Allowed: []string{"visible"}},
			},
		},
	}})

	err, status := middleware.ProcessRequest(httptest.NewRecorder(), req, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Zero(t, store.getCalls)
	assert.Nil(t, ctxGetCacheOptions(req), "bypassed reads must not arm the cache writer")
}

func TestCredentialSpecificMCPFilteringApplies(t *testing.T) {
	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "mcp-api"
		spec.MarkAsMCP()
	})[0]
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	session := &user.SessionState{AccessRights: map[string]user.AccessDefinition{
		spec.APIID: {
			APIID: spec.APIID,
			MCPAccessRights: user.MCPAccessRights{
				Tools: user.AccessControlRules{Blocked: []string{"secret"}},
			},
		},
	}}

	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{Method: mcp.MethodToolsList})
	assert.True(t, credentialSpecificMCPFilteringApplies(spec, req, session))

	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{Method: mcp.MethodPromptsList})
	assert.False(t, credentialSpecificMCPFilteringApplies(spec, req, session), "unrestricted primitive types remain cacheable")

	session.AccessRights[spec.APIID] = user.AccessDefinition{
		APIID: spec.APIID,
		JSONRPCMethodsAccessRights: user.AccessControlRules{
			Blocked: []string{mcp.MethodToolsCall},
		},
	}
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{Method: mcp.MethodInitialize})
	assert.True(t, credentialSpecificMCPFilteringApplies(spec, req, session))

	assert.False(t, credentialSpecificMCPFilteringApplies(spec, req, nil))

	nonMCP := BuildAPI(func(spec *APISpec) { spec.APIID = "http-api" })[0]
	assert.False(t, credentialSpecificMCPFilteringApplies(nonMCP, req, session))
}

func TestResponseCacheMiddleware_SkipsEditedAndStreamingMCPResponses(t *testing.T) {
	for _, tt := range []struct {
		name           string
		contentType    string
		responseEdited bool
	}{
		{name: "credential-specific JSON", contentType: "application/json", responseEdited: true},
		{name: "SSE", contentType: "text/event-stream", responseEdited: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewDummyStorage()
			spec := BuildAPI(func(spec *APISpec) {
				spec.APIID = "mcp-api"
				spec.MarkAsMCP()
				spec.CacheOptions.EnableCache = true
			})[0]
			middleware := &ResponseCacheMiddleware{
				BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec},
				store:                  store,
			}
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			ctxSetCacheOptions(req, &cacheOptions{key: "cache-key", timeout: 60, responseEdited: tt.responseEdited})
			res := &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": []string{tt.contentType}},
				Body:          io.NopCloser(bytes.NewBufferString("payload")),
				ContentLength: 7,
			}

			require.NoError(t, middleware.HandleResponse(httptest.NewRecorder(), res, req, nil))
			assert.Empty(t, store.Data)
		})
	}
}
