package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

func TestMCPDiscoveryJSONSSEParity(t *testing.T) {
	spec := buildMCPListFilterSSESpec("api", nil)
	req := httptest.NewRequest("POST", "/mcp", nil)
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{Method: mcp.MethodServerDiscover, ID: json.Number("9007199254740993")})
	body := []byte(`{"jsonrpc":"2.0","id":9007199254740993,"result":{"supportedVersions":["2099-01-01","2025-03-26","2026-07-28"],"capabilities":{"tools":{},"prompts":{}},"_meta":{"unknown":true},"resultType":"complete"}}`)
	for _, ses := range []*user.SessionState{nil, {AccessRights: map[string]user.AccessDefinition{"api": {JSONRPCMethodsAccessRights: user.AccessControlRules{Blocked: []string{"prompts/get"}}}}}} {
		global, credential := discoveryJSONRPCRuleSets(spec, ses)
		want, changed, _, err := mcp.FilterDiscoveryBody(body, global, credential, spec)
		require.NoError(t, err)
		require.True(t, changed)
		hook := NewMCPListFilterSSEHook(spec, ses, req)
		require.NotNil(t, hook, "keyless discovery still intersects endpoint-supported versions")
		allowed, event := hook.FilterEvent(&SSEEvent{Event: "message", ID: "event-id", Data: []string{string(body)}})
		require.True(t, allowed)
		require.NotNil(t, event)
		require.JSONEq(t, string(want), strings.Join(event.Data, "\n"))
		require.Equal(t, "event-id", event.ID)
	}
	// Unrelated unfiltered streams must not acquire the filtering size guard.
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{Method: mcp.MethodToolsCall})
	require.Nil(t, NewMCPListFilterSSEHook(spec, nil, req))
}

func TestMCPDiscoverySSEFailsClosedAndTerminates(t *testing.T) {
	spec := buildMCPListFilterSSESpec("api", nil)
	requestID := json.Number("9007199254740993")
	newRequest := func() *http.Request {
		req := httptest.NewRequest("POST", "/mcp", nil)
		httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{Method: mcp.MethodServerDiscover, ID: requestID})
		httpctx.SetMCPProtocolContext(req, mcp.NewProtocolContext(mcp.ModernProtocolVersion, "", &mcp.RequestEnvelope{ID: requestID}, nil))
		return req
	}

	t.Run("matching malformed event", func(t *testing.T) {
		hook := NewMCPListFilterSSEHook(spec, nil, newRequest())
		allowed, modified := hook.FilterEvent(&SSEEvent{Event: "message", ID: "event-id", Data: []string{`{"jsonrpc":"2.0","id":9007199254740993,"result":null}`}})
		require.True(t, allowed)
		require.NotNil(t, modified)
		require.True(t, hook.Terminal())
		var response struct {
			ID    json.RawMessage    `json:"id"`
			Error struct{ Code int } `json:"error"`
		}
		require.NoError(t, json.Unmarshal([]byte(strings.Join(modified.Data, "\n")), &response))
		require.Equal(t, "9007199254740993", string(response.ID))
		require.Equal(t, -33006, response.Error.Code)
	})

	t.Run("hybrid method and result is terminal", func(t *testing.T) {
		hook := NewMCPListFilterSSEHook(spec, nil, newRequest())
		allowed, modified := hook.FilterEvent(&SSEEvent{Event: "message", Data: []string{`{"jsonrpc":"2.0","id":9007199254740993,"method":"notifications/progress","result":{"supportedVersions":[],"capabilities":{}}}`}})
		require.True(t, allowed)
		require.NotNil(t, modified)
		require.True(t, hook.Terminal())
		require.Equal(t, 1, strings.Count(strings.Join(modified.Data, "\n"), `"code":-33006`))
	})

	t.Run("unrelated frames pass before matching response", func(t *testing.T) {
		hook := NewMCPListFilterSSEHook(spec, nil, newRequest())
		for _, data := range []string{
			`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`,
			`{"jsonrpc":"2.0","id":"other","result":{"opaque":true}}`,
		} {
			allowed, modified := hook.FilterEvent(&SSEEvent{Data: []string{data}})
			require.True(t, allowed)
			require.Nil(t, modified)
			require.False(t, hook.Terminal())
		}
		valid := `{"jsonrpc":"2.0","id":9007199254740993,"result":{"supportedVersions":["2099-01-01","2026-07-28"],"capabilities":{},"unknown":true}}`
		allowed, modified := hook.FilterEvent(&SSEEvent{Data: []string{valid}})
		require.True(t, allowed)
		require.NotNil(t, modified)
		require.Contains(t, strings.Join(modified.Data, "\n"), mcp.ModernProtocolVersion)
		require.NotContains(t, strings.Join(modified.Data, "\n"), "2099-01-01")
	})

	t.Run("tap drains one error and closes upstream", func(t *testing.T) {
		req := newRequest()
		hook := NewMCPListFilterSSEHook(spec, nil, req)
		input := "data: {\"jsonrpc\":\"2.0\",\"id\":9007199254740993,\"result\":null}\n\n" +
			"data: {\"secret\":\"must-not-pass\"}\n\n"
		upstream := &trackingCloser{Reader: strings.NewReader(input)}
		tap := NewSSETap(upstream, hook)
		output, err := io.ReadAll(tap)
		require.NoError(t, err)
		require.Equal(t, 1, strings.Count(string(output), `"code":-33006`))
		require.NotContains(t, string(output), "must-not-pass")
		require.True(t, upstream.wasClosed())
	})

	t.Run("truncated stream becomes terminal error event", func(t *testing.T) {
		hook := NewMCPListFilterSSEHook(spec, nil, newRequest())
		upstream := &trackingCloser{Reader: strings.NewReader(`data: {"jsonrpc":"2.0"`)}
		output, err := io.ReadAll(NewSSETap(upstream, hook))
		require.NoError(t, err)
		require.Equal(t, 1, strings.Count(string(output), `"code":-33006`))
		require.True(t, upstream.wasClosed())
	})

	t.Run("clean EOF after progress becomes terminal error event", func(t *testing.T) {
		hook := NewMCPListFilterSSEHook(spec, nil, newRequest())
		progress := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`
		upstream := &trackingCloser{Reader: strings.NewReader("data: " + progress + "\n\n")}
		output, err := io.ReadAll(NewSSETap(upstream, hook))
		require.NoError(t, err)
		require.Equal(t, 1, strings.Count(string(output), progress))
		require.Equal(t, 1, strings.Count(string(output), `"code":-33006`))
		require.True(t, upstream.wasClosed())
	})

	t.Run("oversized discovery frames become terminal error events", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			input string
		}{
			{
				name: "complete event",
				input: "data: {\"jsonrpc\":\"2.0\",\"id\":9007199254740993,\"result\":{\"supportedVersions\":[],\"capabilities\":{},\"padding\":\"" +
					strings.Repeat("x", maxInputBufferSize) + "\"}}\n\n",
			},
			{
				name:  "pending event",
				input: "data: {\"padding\":\"" + strings.Repeat("x", maxInputBufferSize),
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				hook := NewMCPListFilterSSEHook(spec, nil, newRequest())
				upstream := &trackingCloser{Reader: strings.NewReader(test.input)}
				output, err := io.ReadAll(NewSSETap(upstream, hook))
				require.NoError(t, err)
				require.Equal(t, 1, strings.Count(string(output), `"code":-33006`))
				require.NotContains(t, string(output), strings.Repeat("x", 32))
				require.True(t, upstream.wasClosed())
			})
		}
	})

	t.Run("credential-specific upstream error disables cache without rewriting", func(t *testing.T) {
		req := newRequest()
		options := &cacheOptions{}
		ctxSetCacheOptions(req, options)
		session := &user.SessionState{AccessRights: map[string]user.AccessDefinition{
			"api": {JSONRPCMethodsAccessRights: user.AccessControlRules{Blocked: []string{"prompts/get"}}},
		}}
		hook := NewMCPListFilterSSEHook(spec, session, req)
		data := `{"jsonrpc":"2.0","id":9007199254740993,"error":{"code":-32001,"message":"upstream","data":{"opaque":true}}}`
		allowed, modified := hook.FilterEvent(&SSEEvent{Event: "message", Data: []string{data}})
		require.True(t, allowed)
		require.Nil(t, modified, "valid upstream error must remain byte-for-byte unchanged")
		require.False(t, hook.Terminal())
		require.True(t, options.responseEdited)
	})

	t.Run("concurrent terminal read and close", func(t *testing.T) {
		for range 20 {
			hook := NewMCPListFilterSSEHook(spec, nil, newRequest())
			upstream := &trackingCloser{Reader: strings.NewReader("data: {\"jsonrpc\":\"2.0\",\"id\":9007199254740993,\"result\":null}\n\n")}
			tap := NewSSETap(upstream, hook)
			var wait sync.WaitGroup
			wait.Add(2)
			go func() {
				defer wait.Done()
				_, _ = io.Copy(io.Discard, tap)
			}()
			go func() {
				defer wait.Done()
				_ = tap.Close()
			}()
			wait.Wait()
			require.True(t, upstream.wasClosed())
		}
	})
}
