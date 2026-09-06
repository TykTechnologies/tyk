package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

type cacheReadCountingStore struct {
	*storage.DummyStorage
	getCalls int
	written  chan struct{}
}

func (s *cacheReadCountingStore) SetKey(key, value string, ttl int64) error {
	err := s.DummyStorage.SetKey(key, value, ttl)
	if s.written != nil {
		s.written <- struct{}{}
	}
	return err
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
	spec.CacheOptions.CacheTimeout = 60
	spec.RxPaths = map[string][]URLSpec{"v1": (APIDefinitionLoader{}).compileCachedPathSpec(nil, []apidef.CacheMeta{{Path: "/mcp", Method: http.MethodPost}}, config.Config{})}
	store := &cacheReadCountingStore{DummyStorage: storage.NewDummyStorage(), written: make(chan struct{}, 1)}
	middleware := &RedisCacheMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}, store: store}
	// First warm the actual configured POST cache path without credential rules.
	// The same credential acquiring filtering rules must bypass that stored result.
	warm := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	_, _ = middleware.ProcessRequest(httptest.NewRecorder(), warm, nil)
	require.Equal(t, 1, store.getCalls, "control request must reach cache lookup")
	require.NotNil(t, ctxGetCacheOptions(warm), "control must arm the cache writer")
	writer := &ResponseCacheMiddleware{BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec}, store: store}
	body := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"hidden"}]}}`
	upstream := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewBufferString(body)), ContentLength: int64(len(body))}
	require.NoError(t, writer.HandleResponse(httptest.NewRecorder(), upstream, warm, nil))
	select {
	case <-store.written:
	case <-time.After(2 * time.Second):
		t.Fatal("cache writer did not populate store")
	}
	require.NotEmpty(t, store.Data, "control request must populate the configured cache")
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
	assert.Equal(t, 1, store.getCalls, "new filtering rules must bypass the populated cache before lookup")
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
