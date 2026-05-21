package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func connectSDKServer(t *testing.T, server *mcpsdk.Server, options ...*mcpsdk.ClientOptions) *mcpsdk.ClientSession {
	t.Helper()

	ctx := context.Background()
	serverTransport, clientTransport := mcpsdk.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, serverSession.Close()) })

	var opts *mcpsdk.ClientOptions
	if len(options) > 0 {
		opts = options[0]
	}
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "adapter-test-client", Version: "v0.0.1"}, opts)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, clientSession.Close()) })

	return clientSession
}

func waitForToolListChanged(t *testing.T, changed <-chan struct{}) {
	t.Helper()

	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for tools/list_changed notification")
	}
}

func TestNewSDKServer_AdvertisesDerivedToolsWithoutListChangedNotifications(t *testing.T) {
	t.Parallel()

	server, err := NewSDKServer(SDKServerConfig{
		Name:  "Orders [MCP adapter]",
		Tools: sampleTools(),
		CallTool: func(context.Context, *oas.DerivedTool, map[string]any) (*Recorder, error) {
			return NewRecorder(), nil
		},
	})
	require.NoError(t, err)

	session := connectSDKServer(t, server)
	init := session.InitializeResult()
	require.NotNil(t, init.Capabilities.Tools)
	assert.False(t, init.Capabilities.Tools.ListChanged)

	list, err := session.ListTools(context.Background(), &mcpsdk.ListToolsParams{})
	require.NoError(t, err)
	require.Len(t, list.Tools, 2)
	assert.Equal(t, "createOrder", list.Tools[0].Name)
	assert.Equal(t, "getOrder", list.Tools[1].Name)
	assert.Equal(t, "fetch an order", list.Tools[1].Description)
	schema := list.Tools[1].InputSchema.(map[string]any)
	assert.Equal(t, "object", schema["type"])
	assert.Equal(t, map[string]any{"id": map[string]any{"type": "string"}}, schema["properties"])
	assert.Equal(t, []any{"id"}, schema["required"])
}

func TestNewSDKServer_CallToolDispatchesDerivedTool(t *testing.T) {
	t.Parallel()

	var (
		calledTool *oas.DerivedTool
		calledArgs map[string]any
	)

	server, err := NewSDKServer(SDKServerConfig{
		Name:  "Orders [MCP adapter]",
		Tools: sampleTools(),
		CallTool: func(_ context.Context, tool *oas.DerivedTool, args map[string]any) (*Recorder, error) {
			calledTool = tool
			calledArgs = args

			rec := NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			rec.WriteHeader(http.StatusAccepted)
			_, err := rec.Write([]byte(`{"ok":true}`))
			require.NoError(t, err)
			return rec, nil
		},
	})
	require.NoError(t, err)

	session := connectSDKServer(t, server)
	result, err := session.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "getOrder",
		Arguments: map[string]any{"id": "42", "verbose": true},
	})
	require.NoError(t, err)

	require.NotNil(t, calledTool)
	assert.Equal(t, "getOrder", calledTool.Name)
	assert.Equal(t, map[string]any{"id": "42", "verbose": true}, calledArgs)
	assert.False(t, result.IsError)
	assert.EqualValues(t, http.StatusAccepted, result.Meta["upstreamHttpStatus"])
	assert.Equal(t, "application/json", result.Meta["upstreamContentType"])
	require.Len(t, result.Content, 1)
	assert.Equal(t, `{"ok":true}`, result.Content[0].(*mcpsdk.TextContent).Text)
}

func TestSDKToolResult_TruncationNoticeIsVisible(t *testing.T) {
	t.Parallel()

	rec := NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	_, err := rec.Write(bytes.Repeat([]byte("{"), BodyTruncationBytes+1))
	require.NoError(t, err)

	result := SDKToolResult(rec)
	assert.Equal(t, true, result.Meta["truncated"])
	require.Len(t, result.Content, 1)
	text := result.Content[0].(*mcpsdk.TextContent).Text
	assert.Contains(t, text, "Tyk truncated the upstream response")
	assert.Contains(t, text, "The content below is incomplete.")
}

func TestSDKAdapter_UpdateToolsAdvertisesAndEmitsListChanged(t *testing.T) {
	t.Parallel()

	adapter, err := NewSDKAdapter(SDKServerConfig{
		Name:  "Orders [MCP adapter]",
		Tools: sampleTools(),
		CallTool: func(context.Context, *oas.DerivedTool, map[string]any) (*Recorder, error) {
			return NewRecorder(), nil
		},
	})
	require.NoError(t, err)

	changed := make(chan struct{}, 1)
	session := connectSDKServer(t, adapter.Server(), &mcpsdk.ClientOptions{
		ToolListChangedHandler: func(context.Context, *mcpsdk.ToolListChangedRequest) {
			changed <- struct{}{}
		},
	})
	init := session.InitializeResult()
	require.NotNil(t, init.Capabilities.Tools)
	assert.True(t, init.Capabilities.Tools.ListChanged)

	updated := []oas.DerivedTool{
		{
			Name:           "getOrder",
			Description:    "fetch an order by id",
			Method:         http.MethodGet,
			PathTemplate:   "/orders/{id}",
			ParamLocations: map[string]string{"id": "path"},
			InputSchema:    map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}}},
		},
		{
			Name:           "listOrders",
			Description:    "list orders",
			Method:         http.MethodGet,
			PathTemplate:   "/orders",
			ParamLocations: map[string]string{"limit": "query"},
			InputSchema:    map[string]any{"type": "object", "properties": map[string]any{"limit": map[string]any{"type": "integer"}}},
		},
	}

	require.NoError(t, adapter.UpdateTools(updated))
	waitForToolListChanged(t, changed)

	list, err := session.ListTools(context.Background(), &mcpsdk.ListToolsParams{})
	require.NoError(t, err)
	require.Len(t, list.Tools, 2)
	assert.Equal(t, "getOrder", list.Tools[0].Name)
	assert.Equal(t, "fetch an order by id", list.Tools[0].Description)
	assert.Equal(t, "listOrders", list.Tools[1].Name)
}

func TestSDKAdapter_StreamableHTTPHandlerNilOptionsReusesStatefulHandlerForListChanged(t *testing.T) {
	t.Parallel()

	adapter, err := NewSDKAdapter(SDKServerConfig{
		Name:  "Orders [MCP adapter]",
		Tools: sampleTools(),
		CallTool: func(context.Context, *oas.DerivedTool, map[string]any) (*Recorder, error) {
			return NewRecorder(), nil
		},
	})
	require.NoError(t, err)

	loopbackHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adapter.StreamableHTTPHandler(nil).ServeHTTP(w, r)
	})

	changed := make(chan struct{}, 1)
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "adapter-streamable-test-client", Version: "v0.0.1"}, &mcpsdk.ClientOptions{
		ToolListChangedHandler: func(context.Context, *mcpsdk.ToolListChangedRequest) {
			changed <- struct{}{}
		},
	})
	session, err := client.Connect(context.Background(), &mcpsdk.StreamableClientTransport{
		Endpoint:   "http://mcp.test/mcp",
		HTTPClient: &http.Client{Transport: loopbackRoundTripper{handler: loopbackHandler}},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, session.Close()) })

	init := session.InitializeResult()
	require.NotNil(t, init.Capabilities.Tools)
	assert.True(t, init.Capabilities.Tools.ListChanged)

	require.NoError(t, adapter.UpdateTools([]oas.DerivedTool{
		{
			Name:           "getOrder",
			Description:    "fetch an order by id",
			Method:         http.MethodGet,
			PathTemplate:   "/orders/{id}",
			ParamLocations: map[string]string{"id": "path"},
			InputSchema:    map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}}},
		},
		{
			Name:           "listOrders",
			Description:    "list orders",
			Method:         http.MethodGet,
			PathTemplate:   "/orders",
			ParamLocations: map[string]string{"limit": "query"},
			InputSchema:    map[string]any{"type": "object", "properties": map[string]any{"limit": map[string]any{"type": "integer"}}},
		},
	}))
	waitForToolListChanged(t, changed)
}

type loopbackRoundTripper struct {
	handler http.Handler
}

func (rt loopbackRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	pr, pw := io.Pipe()
	rw := &loopbackResponseWriter{
		header:        http.Header{},
		body:          pw,
		status:        http.StatusOK,
		headerWritten: make(chan struct{}),
	}

	go func() {
		defer rw.finish()
		rt.handler.ServeHTTP(rw, req)
	}()

	select {
	case <-rw.headerWritten:
		return &http.Response{
			StatusCode: rw.status,
			Status:     http.StatusText(rw.status),
			Header:     rw.header.Clone(),
			Body:       pr,
			Request:    req,
		}, nil
	case <-req.Context().Done():
		_ = pr.CloseWithError(req.Context().Err())
		_ = pw.CloseWithError(req.Context().Err())
		return nil, req.Context().Err()
	}
}

type loopbackResponseWriter struct {
	header http.Header
	body   *io.PipeWriter

	status        int
	headerOnce    sync.Once
	headerWritten chan struct{}
}

func (w *loopbackResponseWriter) Header() http.Header {
	return w.header
}

func (w *loopbackResponseWriter) WriteHeader(status int) {
	w.headerOnce.Do(func() {
		w.status = status
		close(w.headerWritten)
	})
}

func (w *loopbackResponseWriter) Write(p []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.body.Write(p)
}

func (w *loopbackResponseWriter) Flush() {
	w.WriteHeader(http.StatusOK)
}

func (w *loopbackResponseWriter) finish() {
	w.WriteHeader(w.status)
	_ = w.body.Close()
}

func TestNewSDKStreamableHTTPHandler_HandlesInitializeAsJSON(t *testing.T) {
	t.Parallel()

	handler, err := NewSDKStreamableHTTPHandler(SDKServerConfig{
		Name:  "Orders [MCP adapter]",
		Tools: sampleTools(),
		CallTool: func(context.Context, *oas.DerivedTool, map[string]any) (*Recorder, error) {
			return NewRecorder(), nil
		},
	}, nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{
		"jsonrpc":"2.0",
		"id":1,
		"method":"initialize",
		"params":{
			"protocolVersion":"2025-06-18",
			"clientInfo":{"name":"test","version":"v0.0.1"},
			"capabilities":{}
		}
	}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	result := body["result"].(map[string]any)
	assert.Equal(t, "Orders [MCP adapter]", result["serverInfo"].(map[string]any)["name"])
	capabilities := result["capabilities"].(map[string]any)
	tools := capabilities["tools"].(map[string]any)
	assert.NotContains(t, tools, "listChanged")
}
