package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

type minimalMCPResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newMinimalMCPResponseWriter() *minimalMCPResponseWriter {
	return &minimalMCPResponseWriter{header: make(http.Header)}
}

func (w *minimalMCPResponseWriter) Header() http.Header { return w.header }

func (w *minimalMCPResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *minimalMCPResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(data)
}

type allOptionalMCPResponseWriter struct {
	*minimalMCPResponseWriter
	closeNotify chan bool
}

func (w *allOptionalMCPResponseWriter) Flush() {}

func (w *allOptionalMCPResponseWriter) CloseNotify() <-chan bool { return w.closeNotify }

func (w *allOptionalMCPResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	client, server := net.Pipe()
	_ = client.Close()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

func (w *allOptionalMCPResponseWriter) ReadFrom(src io.Reader) (int64, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.ReadFrom(src)
}

func (w *allOptionalMCPResponseWriter) Push(string, *http.PushOptions) error { return nil }

func TestObserveMCPCompletionPreservesResponseWriterInterfaces(t *testing.T) {
	minimal := newMinimalMCPResponseWriter()
	_, wrappedMinimal := observeMCPCompletion(minimal)
	_, hasFlush := wrappedMinimal.(http.Flusher)
	_, hasHijack := wrappedMinimal.(http.Hijacker)
	_, hasReaderFrom := wrappedMinimal.(io.ReaderFrom)
	_, hasPush := wrappedMinimal.(http.Pusher)
	_, hasCloseNotify := wrappedMinimal.(http.CloseNotifier) //nolint:staticcheck
	assert.False(t, hasFlush)
	assert.False(t, hasHijack)
	assert.False(t, hasReaderFrom)
	assert.False(t, hasPush)
	assert.False(t, hasCloseNotify)

	full := &allOptionalMCPResponseWriter{
		minimalMCPResponseWriter: newMinimalMCPResponseWriter(),
		closeNotify:              make(chan bool),
	}
	observer, wrappedFull := observeMCPCompletion(full)
	require.Implements(t, (*http.Flusher)(nil), wrappedFull)
	require.Implements(t, (*http.Hijacker)(nil), wrappedFull)
	require.Implements(t, (*io.ReaderFrom)(nil), wrappedFull)
	require.Implements(t, (*http.Pusher)(nil), wrappedFull)
	require.Implements(t, (*http.CloseNotifier)(nil), wrappedFull) //nolint:staticcheck

	body := `{"jsonrpc":"2.0","id":1,"error":{"code":2147483648,"message":"wide"}}`
	_, err := wrappedFull.(io.ReaderFrom).ReadFrom(strings.NewReader(body))
	require.NoError(t, err)
	status, observed, _ := observer.snapshot(httptest.NewRequest(http.MethodPost, "/mcp", nil))
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, body, string(observed))
}

func TestObserveMCPCompletionIsBoundedAndPassThrough(t *testing.T) {
	underlying := newMinimalMCPResponseWriter()
	observer, wrapped := observeMCPCompletion(underlying)
	body := bytes.Repeat([]byte("x"), mcpCompletionObservationLimit+1024)
	n, err := wrapped.Write(body)
	require.NoError(t, err)
	assert.Equal(t, len(body), n)
	assert.Equal(t, body, underlying.body.Bytes())
	status, observed, _ := observer.snapshot(httptest.NewRequest(http.MethodPost, "/mcp", nil))
	assert.Equal(t, http.StatusOK, status)
	assert.Len(t, observed, mcpCompletionObservationLimit)
}

func TestJSONRPCCompletionErrorCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		code int64
		ok   bool
	}{
		{name: "positive wide JSON", body: `{"jsonrpc":"2.0","error":{"code":2147483648}}`, code: 2147483648, ok: true},
		{name: "minimum int64 JSON", body: `{"jsonrpc":"2.0","error":{"code":-9223372036854775808}}`, code: -9223372036854775808, ok: true},
		{name: "multiline SSE", body: "event: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"error\":{\"code\":-2147483649}}\n\n", code: -2147483649, ok: true},
		{name: "success", body: `{"jsonrpc":"2.0","result":{}}`},
		{name: "nested error", body: `{"result":{"error":{"code":-32000}}}`},
		{name: "string code", body: `{"error":{"code":"-32000"}}`},
		{name: "outside int64", body: `{"error":{"code":9223372036854775808}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, ok := jsonRPCCompletionErrorCode([]byte(tc.body))
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.code, code)
		})
	}
}

type mcpAnalyticsCapture struct {
	mu      sync.Mutex
	records []analytics.AnalyticsRecord
}

func (c *mcpAnalyticsCapture) add(record *analytics.AnalyticsRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, *record)
}

func (c *mcpAnalyticsCapture) snapshot() []analytics.AnalyticsRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]analytics.AnalyticsRecord(nil), c.records...)
}

func pairedMCPCompletionTestHandler(t *testing.T, internal http.Handler) (*DummyProxyHandler, *APISpec, *mcpAnalyticsCapture) {
	t.Helper()
	conf := config.Default
	conf.EnableAnalytics = true
	conf.AnalyticsConfig.EnableDetailedRecording = true
	conf.AnalyticsConfig.AllowUnsafeDetailedLogs = true

	rest := restSourceSpec("rest-analytics", "org-analytics", true)
	proxy := pairedMCPProxySpec("proxy-analytics", "org-analytics", rest.APIID, nil)
	proxy.MarkAsMCP()
	proxy.Name = "Public MCP Analytics"
	proxy.UseKeylessAccess = true
	proxy.DoNotTrack = false
	proxy.Proxy.ListenPath = "/public-mcp/"
	proxy.GlobalConfig = conf
	target, err := url.Parse(proxy.Proxy.TargetURL)
	require.NoError(t, err)
	proxy.target = target
	rest.GlobalConfig = conf

	adapter, err := buildMCPAdapterSpec(rest, []*APISpec{proxy}, nil)
	require.NoError(t, err)
	adapter.GlobalConfig = conf

	gw := &Gateway{
		apisByID: map[string]*APISpec{
			rest.APIID:    rest,
			proxy.APIID:   proxy,
			adapter.APIID: adapter,
		},
		apisHandlesByID: &sync.Map{},
	}
	gw.SetConfig(conf)
	gw.apisHandlesByID.Store(adapter.APIID, &ChainObject{ThisHandler: internal})
	pairing, err := computeMCPPairing([]*APISpec{rest, proxy})
	require.NoError(t, err)
	gw.mcpPairingIndex.Set(pairing)

	capture := &mcpAnalyticsCapture{}
	gw.Analytics.mockEnabled = true
	gw.Analytics.mockRecordHit = capture.add

	return &DummyProxyHandler{
		SH: SuccessHandler{BaseMiddleware: &BaseMiddleware{Spec: proxy, Gw: gw}},
		Gw: gw,
	}, adapter, capture
}

func pairedMCPCompletionRequest(t *testing.T, method, primitiveType, primitiveName, body, userAgent string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://public.example/public-mcp/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	ctxSetMCPMethod(req, method)
	ctxSetMCPPrimitiveType(req, primitiveType)
	ctxSetMCPPrimitiveName(req, primitiveName)
	var envelope mcp.RequestEnvelope
	require.NoError(t, json.Unmarshal([]byte(body), &envelope))
	httpctx.SetMCPProtocolContext(req, mcp.NewProtocolContext("2026-07-28", "", &envelope, []byte(body)))
	ctxSetRequestStartTime(req, time.Now().Add(-time.Millisecond))
	ctxSetOriginalRequestPath(req, req.URL.Path)
	redirect := *req.URL
	ctxSetInternalRedirectTarget(req, &redirect)
	acceptMCPOrigin(req, pairedMCPProxySpec("proxy-analytics", "org-analytics", "rest-analytics", nil), "")
	return req
}

func TestDummyProxyHandlerRecordsPairedMCPCompletionsOnPublicAPI(t *testing.T) {
	internal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/hidden-adapter"
		r.Method = http.MethodPut
		r.Header.Set("User-Agent", "hidden-adapter")
		w.Header().Set("Content-Type", "application/json")
		_, err := io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		require.NoError(t, err)
	})
	handler, adapter, capture := pairedMCPCompletionTestHandler(t, internal)
	assert.True(t, adapter.DoNotTrack, "only the hidden adapter must suppress its own analytics")
	assert.False(t, handler.SH.Spec.DoNotTrack)

	for _, tc := range []struct {
		method        string
		primitiveType string
		primitiveName string
		params        string
	}{
		{method: mcp.MethodInitialize, params: `{"protocolVersion":"2026-07-28","clientInfo":{"name":"client","version":"1"},"capabilities":{}}`},
		{method: mcp.MethodToolsList, params: `{}`},
		{method: mcp.MethodToolsCall, primitiveType: mcp.PrimitiveTypeTool, primitiveName: "orders", params: `{"name":"orders","arguments":{}}`},
	} {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, tc.method, tc.params)
		req := pairedMCPCompletionRequest(t, tc.method, tc.primitiveType, tc.primitiveName, body, "public-agent")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusOK, recorder.Code)
	}

	records := capture.snapshot()
	require.Len(t, records, 3)
	for i, record := range records {
		assert.Equal(t, "proxy-analytics", record.APIID)
		assert.Equal(t, "Public MCP Analytics", record.APIName)
		assert.Equal(t, "org-analytics", record.OrgID)
		assert.Equal(t, "/public-mcp/", record.Path)
		assert.Equal(t, "/public-mcp/", record.RawPath)
		assert.Equal(t, http.MethodPost, record.Method)
		assert.Equal(t, "public-agent", record.UserAgent)
		assert.Equal(t, http.StatusOK, record.ResponseCode)
		assert.Equal(t, "2026-07-28", record.MCPStats.EffectiveProtocolVersion)
		assert.Equal(t, []string{mcp.MethodInitialize, mcp.MethodToolsList, mcp.MethodToolsCall}[i], record.MCPStats.JSONRPCMethod)
		raw, err := base64.StdEncoding.DecodeString(record.RawRequest)
		require.NoError(t, err)
		assert.Contains(t, string(raw), `"jsonrpc":"2.0"`)
		assert.NotContains(t, string(raw), "hidden-adapter")
	}
	assert.Equal(t, mcp.PrimitiveTypeTool, records[2].MCPStats.PrimitiveType)
	assert.Equal(t, "orders", records[2].MCPStats.PrimitiveName)
}

func TestDummyProxyHandlerKeepsConcurrentMCPCompletionAttributionRequestLocal(t *testing.T) {
	internal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := r.Header.Get("X-Completion-Code")
		r.URL.Path = "/hidden-adapter"
		r.Method = http.MethodPatch
		r.Header.Set("User-Agent", "hidden-adapter")
		w.Header().Set("Content-Type", "application/json")
		_, err := fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"error":{"code":%s,"message":"probe"}}`, code)
		require.NoError(t, err)
	})
	handler, _, capture := pairedMCPCompletionTestHandler(t, internal)

	const requests = 12
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("tool-%02d", i)
			agent := fmt.Sprintf("agent-%02d", i)
			body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, i, name)
			req := pairedMCPCompletionRequest(t, mcp.MethodToolsCall, mcp.PrimitiveTypeTool, name, body, agent)
			req.Header.Set("X-Completion-Code", fmt.Sprintf("%d", int64(2147483648)+int64(i)))
			handler.ServeHTTP(httptest.NewRecorder(), req)
		}(i)
	}
	wg.Wait()

	records := capture.snapshot()
	require.Len(t, records, requests)
	byAgent := make(map[string]analytics.AnalyticsRecord, requests)
	for _, record := range records {
		byAgent[record.UserAgent] = record
	}
	for i := 0; i < requests; i++ {
		agent := fmt.Sprintf("agent-%02d", i)
		record, ok := byAgent[agent]
		require.True(t, ok)
		assert.Equal(t, fmt.Sprintf("tool-%02d", i), record.MCPStats.PrimitiveName)
		assert.Equal(t, int64(2147483648)+int64(i), record.MCPStats.JSONRPCErrorCode)
		assert.Equal(t, "/public-mcp/", record.Path)
		raw, err := base64.StdEncoding.DecodeString(record.RawRequest)
		require.NoError(t, err)
		assert.Contains(t, string(raw), fmt.Sprintf(`"id":%d`, i))
	}
}

func TestDummyProxyHandlerRecordsNoCommitAs499AndPreservesPanic(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		handler, _, capture := pairedMCPCompletionTestHandler(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
		req := pairedMCPCompletionRequest(t, mcp.MethodToolsList, "", "", body, "cancelled-agent")
		ctx, cancel := context.WithCancel(req.Context())
		cancel()
		req = req.WithContext(ctx)
		handler.ServeHTTP(httptest.NewRecorder(), req)
		records := capture.snapshot()
		require.Len(t, records, 1)
		assert.Equal(t, 499, records[0].ResponseCode)
	})

	t.Run("panic", func(t *testing.T) {
		handler, _, capture := pairedMCPCompletionTestHandler(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("sdk panic")
		}))
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
		req := pairedMCPCompletionRequest(t, mcp.MethodToolsList, "", "", body, "panic-agent")
		assert.PanicsWithValue(t, "sdk panic", func() {
			handler.ServeHTTP(httptest.NewRecorder(), req)
		})
		records := capture.snapshot()
		require.Len(t, records, 1)
		assert.Equal(t, 499, records[0].ResponseCode)
	})
}
