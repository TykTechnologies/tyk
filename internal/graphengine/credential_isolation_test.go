package graphengine

// Shared fixtures for the upstream credential isolation tests. The defect these guard
// against is a cached execution plan that carries the first caller's upstream auth
// header, so every test here drives at least two callers with different credentials
// through one engine and asserts what each upstream connection actually received.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	nhooyrwebsocket "github.com/coder/websocket"
	gorillawebsocket "github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	graphqlv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
)

const (
	// The two upstream WebSocket protocols that a data source can be configured with.
	// They differ in the message type that carries a payload.
	protocolGraphQLWS          = "graphql-ws"
	protocolGraphQLTransportWS = "graphql-transport-ws"
	messageTypeData            = "data" // graphql-ws
	messageTypeNext            = "next" // graphql-transport-ws

	isolationTestSchema = "type Query { hello: String } type Subscription { count: Int }"
)

// authorizationRecorder records the credential that each upstream connection carried,
// in the order the upstream saw them.
type authorizationRecorder struct {
	// headerName is the request header that values() reports. Empty means Authorization.
	headerName string

	mu       sync.Mutex
	received []http.Header
}

func newAuthorizationRecorder(headerName string) *authorizationRecorder {
	return &authorizationRecorder{headerName: headerName}
}

func (r *authorizationRecorder) header() string {
	if r.headerName == "" {
		return "Authorization"
	}
	return r.headerName
}

func (r *authorizationRecorder) recordRequest(request *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.received = append(r.received, request.Header.Clone())
}

// values returns the credential of every recorded upstream connection, in order.
func (r *authorizationRecorder) values() []string {
	return r.headerValues(r.header())
}

// headerValues returns the value of name for every recorded upstream connection, in order.
// Only the first value of each, so it cannot see a header the upstream received twice - use
// headerValueLists for that.
func (r *authorizationRecorder) headerValues(name string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	values := make([]string, 0, len(r.received))
	for _, recorded := range r.received {
		values = append(values, recorded.Get(name))
	}
	return values
}

// headerValueLists returns every value of name that each recorded upstream connection carried.
// A credential forwarded twice shows up here and nowhere else: two writers put the caller's
// auth header on a proxy-only request, the engine through propagateAuthHeaders and the
// transport through setProxyOnlyHeaders.
func (r *authorizationRecorder) headerValueLists(name string) [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	values := make([][]string, 0, len(r.received))
	for _, recorded := range r.received {
		values = append(values, recorded.Values(name))
	}
	return values
}

// authorizationRecordingRoundTripper records the credential of every upstream fetch and
// answers with a valid GraphQL response. Proxy-only mode reads the header and the status
// code of this response back out of the proxy-only context, so both are populated.
type authorizationRecordingRoundTripper struct {
	*authorizationRecorder
}

func newAuthorizationRecordingRoundTripper() *authorizationRecordingRoundTripper {
	return &authorizationRecordingRoundTripper{authorizationRecorder: newAuthorizationRecorder("")}
}

func (r *authorizationRecordingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	r.recordRequest(request)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(`{"data":{"hello":"world"}}`)),
		Request:    request,
	}, nil
}

// newRecordingSSEUpstream serves a single subscription event over server sent events.
func newRecordingSSEUpstream(t *testing.T, recorder *authorizationRecorder) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.recordRequest(request)
		writer.Header().Set("Content-Type", "text/event-stream")
		_, err := io.WriteString(writer, "event: next\ndata: {\"data\":{\"count\":1}}\n\nevent: complete\n\n")
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	return server
}

// newRecordingWSUpstream serves subscription events over a WebSocket connection.
// subprotocol selects the protocol to negotiate and dataMessageType the message type that
// carries the payload: graphql-ws uses "data", graphql-transport-ws uses "next".
//
// It answers every subscription that arrives on the connection, not just the first. Most
// tests open one connection per caller and so only ever use the first, but a test that
// asserts callers are not multiplexed onto one upstream connection needs the multiplexed
// ones to be served as well: otherwise they never complete and the test hangs instead of
// reporting the shared connection.
func newRecordingWSUpstream(t *testing.T, recorder *authorizationRecorder, subprotocol, dataMessageType string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.recordRequest(request)
		serveRecordingWSConnection(writer, request, subprotocol, dataMessageType)
	}))
	t.Cleanup(server.Close)
	return server
}

// serveRecordingWSConnection accepts the WebSocket connection, acknowledges the handshake
// and then answers every subscription that arrives on it.
//
// It runs on a hijacked connection, which httptest.Server.Close does not wait for, so it
// must never touch *testing.T: the goroutine can outlive the test. Every failure path
// therefore just returns and lets the test observe the missing payload.
func serveRecordingWSConnection(writer http.ResponseWriter, request *http.Request, subprotocol, dataMessageType string) {
	connection, err := nhooyrwebsocket.Accept(writer, request, &nhooyrwebsocket.AcceptOptions{
		Subprotocols: []string{subprotocol},
	})
	if err != nil {
		return
	}
	defer connection.CloseNow() //nolint:errcheck // hijacked handler, cannot touch t; net.ErrClosed is the normal path

	ctx := request.Context()
	// connection_init
	if _, _, err = connection.Read(ctx); err != nil {
		return
	}
	if err = connection.Write(ctx, nhooyrwebsocket.MessageText, []byte(`{"type":"connection_ack"}`)); err != nil {
		return
	}
	// start / subscribe, once per subscription multiplexed onto this connection
	for {
		_, message, err := connection.Read(ctx)
		if err != nil {
			return
		}
		if err = answerWSSubscription(ctx, connection, message, dataMessageType); err != nil {
			return
		}
	}
}

// answerWSSubscription answers one start message with a single payload followed by a
// complete. Anything else is a stop, a complete or a keep alive, which carries no
// subscription to answer, so it is ignored.
func answerWSSubscription(ctx context.Context, connection *nhooyrwebsocket.Conn, message []byte, dataMessageType string) error {
	var start struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(message, &start); err != nil {
		return err
	}
	if start.Type != "start" && start.Type != "subscribe" {
		return nil
	}
	data := fmt.Sprintf(`{"type":%q,"id":%q,"payload":{"data":{"count":1}}}`, dataMessageType, start.ID)
	if err := connection.Write(ctx, nhooyrwebsocket.MessageText, []byte(data)); err != nil {
		return err
	}
	complete := fmt.Sprintf(`{"type":"complete","id":%q}`, start.ID)
	return connection.Write(ctx, nhooyrwebsocket.MessageText, []byte(complete))
}

// closeWSConnection closes connection and fails the test on anything other than the
// expected already-closed error: coder/websocket reports net.ErrClosed when the peer
// closed first, which is how these subscriptions normally end.
func closeWSConnection(t *testing.T, connection *nhooyrwebsocket.Conn) {
	t.Helper()
	if err := connection.CloseNow(); err != nil && !errors.Is(err, net.ErrClosed) {
		assert.NoError(t, err)
	}
}

// isolationContextHeaderVariable matches the $tyk_context.headers_<Name> form, where the
// dashes of the header name are written as underscores.
var isolationContextHeaderVariable = regexp.MustCompile(`\$tyk_context\.headers_([A-Za-z0-9_]+)`)

// isolationVariableReplacer stands in for Gateway.ReplaceTykVariables. It resolves against
// the request being served, so a value that belongs to another caller stays visible as that
// caller's value rather than silently becoming correct.
func isolationVariableReplacer(request *http.Request, value string, _ bool) string {
	return isolationContextHeaderVariable.ReplaceAllStringFunc(value, func(match string) string {
		name := strings.ReplaceAll(strings.TrimPrefix(match, "$tyk_context.headers_"), "_", "-")
		return request.Header.Get(name)
	})
}

// newIsolationEngineV2 builds a real EngineV2 that answers every request with operation.
// The gateway hands one client per API to both the http and the streaming client, so the
// tests do the same.
func newIsolationEngineV2(t *testing.T, apiDefinition *apidef.APIDefinition, operation string) *EngineV2 {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	client := &http.Client{}
	engine, err := NewEngineV2(EngineV2Options{
		Logger:          logger,
		ApiDefinition:   apiDefinition,
		HttpClient:      client,
		StreamingClient: client,
		Injections: EngineV2Injections{
			ContextRetrieveRequest: func(*http.Request) *graphql.Request {
				return &graphql.Request{Query: operation}
			},
			NewReusableBodyReadCloser: testReusableReadCloser,
			TykVariableReplacer:       isolationVariableReplacer,
		},
	})
	require.NoError(t, err)
	t.Cleanup(engine.Cancel)
	return engine
}

// newIsolationEngineV3 builds a real EngineV3 that answers every request with operation.
func newIsolationEngineV3(t *testing.T, apiDefinition *apidef.APIDefinition, operation string) *EngineV3 {
	t.Helper()
	schema, err := graphqlv2.NewSchemaFromString(apiDefinition.GraphQL.Schema)
	require.NoError(t, err)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	client := &http.Client{}
	engine, err := NewEngineV3(EngineV3Options{
		Logger:          logger,
		Schema:          schema,
		ApiDefinition:   apiDefinition,
		HttpClient:      client,
		StreamingClient: client,
		Injections: EngineV3Injections{
			ContextRetrieveRequest: func(*http.Request) *graphqlv2.Request {
				return &graphqlv2.Request{Query: operation}
			},
			NewReusableBodyReadCloser: testReusableReadCloser,
			TykVariableReplacer:       isolationVariableReplacer,
		},
	})
	require.NoError(t, err)
	t.Cleanup(engine.Cancel)
	return engine
}

// callerRequest builds a gateway request that carries credential in headerName. An empty
// credential produces a request without the header, which is the unauthenticated caller.
// extraHeaders are set verbatim, which lets a test tell one caller from another by a header
// that only proxy-only header forwarding copies upstream.
func callerRequest(t *testing.T, headerName, credential string, extraHeaders map[string]string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://gateway.example/graphql", nil)
	require.NoError(t, err)
	if credential != "" {
		if headerName == "" {
			headerName = "Authorization"
		}
		request.Header.Set(headerName, credential)
	}
	for key, value := range extraHeaders {
		request.Header.Set(key, value)
	}
	return request
}

// callAs drives one request through the engine and releases the response body.
func callAs(t *testing.T, engine Engine, roundTripper http.RoundTripper, headerName, credential string) {
	t.Helper()
	callAsWithHeaders(t, engine, roundTripper, headerName, credential, nil)
}

func callAsWithHeaders(t *testing.T, engine Engine, roundTripper http.RoundTripper, headerName, credential string, extraHeaders map[string]string) {
	t.Helper()
	response, _, err := engine.HandleReverseProxy(ReverseProxyParams{
		RoundTripper: roundTripper,
		OutRequest:   callerRequest(t, headerName, credential, extraHeaders),
		NeedsEngine:  true,
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	_ = response.Body.Close()
}

// newUDGApiDefinition builds an execution engine (UDG) API with a single REST data source
// for queries.
func newUDGApiDefinition(version apidef.GraphQLConfigVersion, upstreamURL string) *apidef.APIDefinition {
	apiDefinition := newTestApiDefinitionV2(apidef.GraphQLExecutionModeExecutionEngine, upstreamURL)
	apiDefinition.GraphQL.Version = version
	apiDefinition.UseStandardAuth = true
	apiDefinition.StripAuthData = false
	return apiDefinition
}

// newUDGSubscriptionApiDefinition builds an execution engine (UDG) API with a single GraphQL
// data source that serves the count subscription over subscriptionType.
func newUDGSubscriptionApiDefinition(t *testing.T, version apidef.GraphQLConfigVersion, subscriptionType apidef.SubscriptionType, upstreamURL string) *apidef.APIDefinition {
	t.Helper()
	dataSourceConfig, err := json.Marshal(apidef.GraphQLEngineDataSourceConfigGraphQL{
		URL:              upstreamURL,
		Method:           http.MethodPost,
		SubscriptionType: subscriptionType,
		SSEUsePost:       subscriptionType == apidef.GQLSubscriptionSSE,
	})
	require.NoError(t, err)
	return &apidef.APIDefinition{
		UseStandardAuth: true,
		GraphQL: apidef.GraphQLConfig{
			Enabled:       true,
			ExecutionMode: apidef.GraphQLExecutionModeExecutionEngine,
			Version:       version,
			Schema:        isolationTestSchema,
			Engine: apidef.GraphQLEngineConfig{DataSources: []apidef.GraphQLEngineDataSource{{
				Kind:       apidef.GraphQLEngineDataSourceKindGraphQL,
				Name:       "subscription",
				RootFields: []apidef.GraphQLTypeFields{{Type: "Subscription", Fields: []string{"count"}}},
				Config:     dataSourceConfig,
			}}},
		},
	}
}

// newProxyOnlyApiDefinition builds a proxy-only API. Proxy-only reaches the engine for
// config version 2 and 3-preview, see needsGraphQLExecutionEngine in gateway/mw_graphql.go.
func newProxyOnlyApiDefinition(version apidef.GraphQLConfigVersion, targetURL string, subscriptionType apidef.SubscriptionType) *apidef.APIDefinition {
	apiDefinition := &apidef.APIDefinition{
		UseStandardAuth: true,
		GraphQL: apidef.GraphQLConfig{
			Enabled:       true,
			ExecutionMode: apidef.GraphQLExecutionModeProxyOnly,
			Version:       version,
			Schema:        isolationTestSchema,
			Proxy: apidef.GraphQLProxyConfig{
				SubscriptionType: subscriptionType,
				// Engine v3 proxy-only has no SSEUsePost equivalent, so SSE is a GET there.
				SSEUsePost: subscriptionType == apidef.GQLSubscriptionSSE && version == apidef.GraphQLConfigVersion2,
			},
		},
	}
	apiDefinition.Proxy.TargetURL = targetURL
	return apiDefinition
}

// assertHeaderArrivedOnce fails if any recorded upstream connection carried name more than
// once. Proxy-only has two writers for the caller's auth header and neither knows about the
// other, so a duplicate is the default failure mode rather than an exotic one.
func assertHeaderArrivedOnce(t *testing.T, recorder *authorizationRecorder, name string) {
	t.Helper()
	for i, values := range recorder.headerValueLists(name) {
		assert.LessOrEqual(t, len(values), 1,
			"upstream connection %d received %s %d times: %v", i, name, len(values), values)
	}
}

// waitForUpstreamCalls waits for count upstream connections. The engine v3 resolver
// completes fetches asynchronously, so unlike the v2 tests those have to poll.
func waitForUpstreamCalls(t *testing.T, recorder *authorizationRecorder, count int) {
	t.Helper()
	require.Eventually(t, func() bool {
		return len(recorder.values()) == count
	}, 5*time.Second, 10*time.Millisecond)
}

// --- Proxy-only mode -------------------------------------------------------------
//
// Proxy-only reaches the engine on config version 2 and 3-preview, see
// needsGraphQLExecutionEngine in gateway/mw_graphql.go. It is also the only mode that
// takes GraphQLEngineTransport.handleProxyOnly and therefore the per-request
// headersConfig, so the HTTP cases assert a plain caller header was forwarded too:
// only setProxyOnlyHeaders copies that upstream.

func TestEngineV2_ProxyOnlyHTTPIsolatesCallerAuthorization(t *testing.T) {
	engine := newIsolationEngineV2(t,
		newProxyOnlyApiDefinition(apidef.GraphQLConfigVersion2, "http://upstream.example/graphql", apidef.GQLSubscriptionUndefined),
		"query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	for _, caller := range []string{"a", "b"} {
		callAsWithHeaders(t, engine, upstream, "", "Bearer "+caller, map[string]string{"X-Caller": caller})
	}

	assert.Equal(t, []string{"Bearer a", "Bearer b"}, upstream.values())
	// Proves the proxy-only branch of the transport ran: nothing else forwards X-Caller.
	assert.Equal(t, []string{"a", "b"}, upstream.headerValues("X-Caller"))
	assertHeaderArrivedOnce(t, upstream.authorizationRecorder, "Authorization")
}

func TestEngineV2_ProxyOnlySSESubscriptionIsolatesCallerAuthorization(t *testing.T) {
	upstream := newAuthorizationRecorder("")
	server := newRecordingSSEUpstream(t, upstream)
	engine := newIsolationEngineV2(t,
		newProxyOnlyApiDefinition(apidef.GraphQLConfigVersion2, server.URL, apidef.GQLSubscriptionSSE),
		"subscription { count }")

	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, http.DefaultTransport, "", token)
	}

	assert.Equal(t, []string{"Bearer AAA", "Bearer BBB"}, upstream.values())
	assertHeaderArrivedOnce(t, upstream, "Authorization")
}

func TestEngineV2_ProxyOnlyWebSocketSubscriptionIsolatesCallerAuthorization(t *testing.T) {
	upstream := newAuthorizationRecorder("")
	server := newRecordingWSUpstream(t, upstream, protocolGraphQLWS, messageTypeData)
	engine := newIsolationEngineV2(t,
		newProxyOnlyApiDefinition(apidef.GraphQLConfigVersion2, server.URL, apidef.GQLSubscriptionWS),
		"subscription { count }")

	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, http.DefaultTransport, "", token)
	}

	assert.Equal(t, []string{"Bearer AAA", "Bearer BBB"}, upstream.values())
	assertHeaderArrivedOnce(t, upstream, "Authorization")
}

func TestEngineV3_ProxyOnlyHTTPIsolatesCallerAuthorization(t *testing.T) {
	engine := newIsolationEngineV3(t,
		newProxyOnlyApiDefinition(apidef.GraphQLConfigVersion3Preview, "http://upstream.example/graphql", apidef.GQLSubscriptionUndefined),
		"query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	for _, caller := range []string{"a", "b"} {
		callAsWithHeaders(t, engine, upstream, "", "Bearer "+caller, map[string]string{"X-Caller": caller})
	}

	waitForUpstreamCalls(t, upstream.authorizationRecorder, 2)
	assert.ElementsMatch(t, []string{"Bearer a", "Bearer b"}, upstream.values())
	assert.ElementsMatch(t, []string{"a", "b"}, upstream.headerValues("X-Caller"))
	assertHeaderArrivedOnce(t, upstream.authorizationRecorder, "Authorization")
}

func TestEngineV3_ProxyOnlySSESubscriptionIsolatesCallerAuthorization(t *testing.T) {
	upstream := newAuthorizationRecorder("")
	server := newRecordingSSEUpstream(t, upstream)
	engine := newIsolationEngineV3(t,
		newProxyOnlyApiDefinition(apidef.GraphQLConfigVersion3Preview, server.URL, apidef.GQLSubscriptionSSE),
		"subscription { count }")

	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, http.DefaultTransport, "", token)
	}

	waitForUpstreamCalls(t, upstream, 2)
	assert.ElementsMatch(t, []string{"Bearer AAA", "Bearer BBB"}, upstream.values())
	assertHeaderArrivedOnce(t, upstream, "Authorization")
}

func TestEngineV3_ProxyOnlyWebSocketSubscriptionIsolatesCallerAuthorization(t *testing.T) {
	upstream := newAuthorizationRecorder("")
	server := newRecordingWSUpstream(t, upstream, protocolGraphQLWS, messageTypeData)
	engine := newIsolationEngineV3(t,
		newProxyOnlyApiDefinition(apidef.GraphQLConfigVersion3Preview, server.URL, apidef.GQLSubscriptionWS),
		"subscription { count }")

	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, http.DefaultTransport, "", token)
	}

	waitForUpstreamCalls(t, upstream, 2)
	assert.ElementsMatch(t, []string{"Bearer AAA", "Bearer BBB"}, upstream.values())
	assertHeaderArrivedOnce(t, upstream, "Authorization")
}

// The reported shape: proxy-only, strip_auth_data off, a custom auth header name that the
// consumer sends. The engine adds it to the fetch input through propagateAuthHeaders and the
// transport forwards it again, so the upstream used to see the credential twice.
func newProxyOnlyCustomAuthApiDefinition(version apidef.GraphQLConfigVersion, targetURL string) *apidef.APIDefinition {
	apiDefinition := newProxyOnlyApiDefinition(version, targetURL, apidef.GQLSubscriptionUndefined)
	apiDefinition.AuthConfigs = map[string]apidef.AuthConfig{
		apidef.AuthTokenType: {AuthHeaderName: "X-Api-Key"},
	}
	return apiDefinition
}

func TestEngineV2_ProxyOnlyForwardsTheCallerCredentialOnce(t *testing.T) {
	engine := newIsolationEngineV2(t,
		newProxyOnlyCustomAuthApiDefinition(apidef.GraphQLConfigVersion2, "http://upstream.example/graphql"),
		"query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	for _, key := range []string{"key-aaa", "key-bbb"} {
		callAs(t, engine, upstream, "X-Api-Key", key)
	}

	assert.Equal(t, [][]string{{"key-aaa"}, {"key-bbb"}}, upstream.headerValueLists("X-Api-Key"))
}

func TestEngineV3_ProxyOnlyForwardsTheCallerCredentialOnce(t *testing.T) {
	engine := newIsolationEngineV3(t,
		newProxyOnlyCustomAuthApiDefinition(apidef.GraphQLConfigVersion3Preview, "http://upstream.example/graphql"),
		"query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	for _, key := range []string{"key-aaa", "key-bbb"} {
		callAs(t, engine, upstream, "X-Api-Key", key)
	}

	waitForUpstreamCalls(t, upstream.authorizationRecorder, 2)
	assert.ElementsMatch(t, [][]string{{"key-aaa"}, {"key-bbb"}}, upstream.headerValueLists("X-Api-Key"))
}

// --- graphql-transport-ws --------------------------------------------------------
//
// The second upstream WebSocket protocol has its own handler in the library. The
// graphql-ws tests above cover the legacy one.

func TestEngineV2_TransportWSSubscriptionIsolatesCallerAuthorization(t *testing.T) {
	upstream := newAuthorizationRecorder("")
	server := newRecordingWSUpstream(t, upstream, protocolGraphQLTransportWS, messageTypeNext)
	engine := newIsolationEngineV2(t,
		newUDGSubscriptionApiDefinition(t, apidef.GraphQLConfigVersion2, apidef.GQLSubscriptionTransportWS, server.URL),
		"subscription { count }")

	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, http.DefaultTransport, "", token)
	}

	assert.Equal(t, []string{"Bearer AAA", "Bearer BBB"}, upstream.values())
}

func TestEngineV3_TransportWSSubscriptionIsolatesCallerAuthorization(t *testing.T) {
	upstream := newAuthorizationRecorder("")
	server := newRecordingWSUpstream(t, upstream, protocolGraphQLTransportWS, messageTypeNext)
	engine := newIsolationEngineV3(t,
		newUDGSubscriptionApiDefinition(t, apidef.GraphQLConfigVersion3Preview, apidef.GQLSubscriptionTransportWS, server.URL),
		"subscription { count }")

	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, http.DefaultTransport, "", token)
	}

	waitForUpstreamCalls(t, upstream, 2)
	assert.ElementsMatch(t, []string{"Bearer AAA", "Bearer BBB"}, upstream.values())
}

// --- Negative controls -----------------------------------------------------------

// An unauthenticated caller after an authenticated one is the reported defect shape: a
// stale, only-if-absent header modifier hands the second caller the first caller's
// credential instead of leaving the header unset.
func TestEngineV2_UnauthenticatedCallerDoesNotInheritCredential(t *testing.T) {
	t.Run("execution engine", func(t *testing.T) {
		engine := newIsolationEngineV2(t,
			newUDGApiDefinition(apidef.GraphQLConfigVersion2, "http://upstream.example/graphql"),
			"query { hello }")

		upstream := newAuthorizationRecordingRoundTripper()
		callAs(t, engine, upstream, "", "Bearer AAA")
		callAs(t, engine, upstream, "", "")

		assert.Equal(t, []string{"Bearer AAA", ""}, upstream.values())
	})

	t.Run("proxy only", func(t *testing.T) {
		engine := newIsolationEngineV2(t,
			newProxyOnlyApiDefinition(apidef.GraphQLConfigVersion2, "http://upstream.example/graphql", apidef.GQLSubscriptionUndefined),
			"query { hello }")

		upstream := newAuthorizationRecordingRoundTripper()
		callAs(t, engine, upstream, "", "Bearer AAA")
		callAs(t, engine, upstream, "", "")

		assert.Equal(t, []string{"Bearer AAA", ""}, upstream.values())
	})
}

func TestEngineV3_UnauthenticatedCallerDoesNotInheritCredential(t *testing.T) {
	t.Run("execution engine", func(t *testing.T) {
		engine := newIsolationEngineV3(t,
			newUDGApiDefinition(apidef.GraphQLConfigVersion3Preview, "http://upstream.example/graphql"),
			"query { hello }")

		upstream := newAuthorizationRecordingRoundTripper()
		callAs(t, engine, upstream, "", "Bearer AAA")
		callAs(t, engine, upstream, "", "")

		waitForUpstreamCalls(t, upstream.authorizationRecorder, 2)
		assert.ElementsMatch(t, []string{"Bearer AAA", ""}, upstream.values())
	})

	t.Run("proxy only", func(t *testing.T) {
		engine := newIsolationEngineV3(t,
			newProxyOnlyApiDefinition(apidef.GraphQLConfigVersion3Preview, "http://upstream.example/graphql", apidef.GQLSubscriptionUndefined),
			"query { hello }")

		upstream := newAuthorizationRecordingRoundTripper()
		callAs(t, engine, upstream, "", "Bearer AAA")
		callAs(t, engine, upstream, "", "")

		waitForUpstreamCalls(t, upstream.authorizationRecorder, 2)
		assert.ElementsMatch(t, []string{"Bearer AAA", ""}, upstream.values())
	})
}

// StripAuthData has to keep the credential away from the upstream. This is execution
// engine only on purpose: in proxy-only mode setProxyOnlyHeaders forwards every caller
// header regardless, and the gateway strips the auth data before the engine sees it.
func TestEngineV2_StripAuthDataKeepsCredentialFromUpstream(t *testing.T) {
	apiDefinition := newUDGApiDefinition(apidef.GraphQLConfigVersion2, "http://upstream.example/graphql")
	apiDefinition.StripAuthData = true
	engine := newIsolationEngineV2(t, apiDefinition, "query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, upstream, "", token)
	}

	assert.Equal(t, []string{"", ""}, upstream.values())
}

func TestEngineV3_StripAuthDataKeepsCredentialFromUpstream(t *testing.T) {
	apiDefinition := newUDGApiDefinition(apidef.GraphQLConfigVersion3Preview, "http://upstream.example/graphql")
	apiDefinition.StripAuthData = true
	engine := newIsolationEngineV3(t, apiDefinition, "query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, upstream, "", token)
	}

	waitForUpstreamCalls(t, upstream.authorizationRecorder, 2)
	assert.Equal(t, []string{"", ""}, upstream.values())
}

// A custom auth header name has to be isolated per caller too, and must not fall back to
// Authorization.
func TestEngineV2_CustomAuthHeaderNameIsolatesCallerCredential(t *testing.T) {
	apiDefinition := newUDGApiDefinition(apidef.GraphQLConfigVersion2, "http://upstream.example/graphql")
	apiDefinition.AuthConfigs = map[string]apidef.AuthConfig{
		apidef.AuthTokenType: {AuthHeaderName: "X-Api-Key"},
	}
	engine := newIsolationEngineV2(t, apiDefinition, "query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	for _, key := range []string{"key-aaa", "key-bbb"} {
		callAs(t, engine, upstream, "X-Api-Key", key)
	}

	assert.Equal(t, []string{"key-aaa", "key-bbb"}, upstream.headerValues("X-Api-Key"))
	assert.Equal(t, []string{"", ""}, upstream.headerValues("Authorization"))
}

func TestEngineV3_CustomAuthHeaderNameIsolatesCallerCredential(t *testing.T) {
	apiDefinition := newUDGApiDefinition(apidef.GraphQLConfigVersion3Preview, "http://upstream.example/graphql")
	apiDefinition.AuthConfigs = map[string]apidef.AuthConfig{
		apidef.AuthTokenType: {AuthHeaderName: "X-Api-Key"},
	}
	engine := newIsolationEngineV3(t, apiDefinition, "query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	for _, key := range []string{"key-aaa", "key-bbb"} {
		callAs(t, engine, upstream, "X-Api-Key", key)
	}

	waitForUpstreamCalls(t, upstream.authorizationRecorder, 2)
	assert.ElementsMatch(t, []string{"key-aaa", "key-bbb"}, upstream.headerValues("X-Api-Key"))
	assert.Equal(t, []string{"", ""}, upstream.headerValues("Authorization"))
}

// --- Concurrency -----------------------------------------------------------------
//
// The defect is a shared state defect, so the sequential tests above are the weaker
// case. Every caller gets a unique credential and the multiset has to come back intact:
// ElementsMatch catches a lost credential and a duplicated one alike.
//
// The tests come in two shapes. The warm ones send a request before fanning out, so the
// execution plan is cached when the burst starts, which is the state the credential defect
// needs and the state of any API that has served a request. The cold ones start with
// nothing cached, which is what exercises the lazily initialised state inside
// graphql-go-tools: the schema hash and the info of a cached plan were both filled in on
// first use, so a cold burst raced on them. Both are fixed as of the pinned
// graphql-go-tools 1ff2d4d7.

const concurrentIsolationCallers = 20

func concurrentCredentials() []string {
	credentials := make([]string, 0, concurrentIsolationCallers)
	for i := 0; i < concurrentIsolationCallers; i++ {
		credentials = append(credentials, fmt.Sprintf("Bearer caller-%02d", i))
	}
	return credentials
}

// callConcurrently drives one request per credential at the same time.
func callConcurrently(t *testing.T, engine Engine, roundTripper http.RoundTripper, credentials []string) {
	t.Helper()
	var waitGroup sync.WaitGroup
	for _, credential := range credentials {
		waitGroup.Add(1)
		go func(credential string) {
			defer waitGroup.Done()
			callAs(t, engine, roundTripper, "", credential)
		}(credential)
	}
	waitGroup.Wait()
}

func TestEngineV2_ConcurrentColdCallersDoNotShareCredentials(t *testing.T) {
	engine := newIsolationEngineV2(t,
		newUDGApiDefinition(apidef.GraphQLConfigVersion2, "http://upstream.example/graphql"),
		"query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	credentials := concurrentCredentials()
	callConcurrently(t, engine, upstream, credentials)

	assert.ElementsMatch(t, credentials, upstream.values())
}

func TestEngineV3_ConcurrentColdCallersDoNotShareCredentials(t *testing.T) {
	engine := newIsolationEngineV3(t,
		newUDGApiDefinition(apidef.GraphQLConfigVersion3Preview, "http://upstream.example/graphql"),
		"query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	credentials := concurrentCredentials()
	callConcurrently(t, engine, upstream, credentials)

	waitForUpstreamCalls(t, upstream.authorizationRecorder, len(credentials))
	assert.ElementsMatch(t, credentials, upstream.values())
}

func TestEngineV2_ConcurrentCallersDoNotShareCredentials(t *testing.T) {
	engine := newIsolationEngineV2(t,
		newUDGApiDefinition(apidef.GraphQLConfigVersion2, "http://upstream.example/graphql"),
		"query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	callAs(t, engine, upstream, "", "Bearer warm-up")

	credentials := concurrentCredentials()
	callConcurrently(t, engine, upstream, credentials)

	assert.ElementsMatch(t, append([]string{"Bearer warm-up"}, credentials...), upstream.values())
}

func TestEngineV3_ConcurrentCallersDoNotShareCredentials(t *testing.T) {
	engine := newIsolationEngineV3(t,
		newUDGApiDefinition(apidef.GraphQLConfigVersion3Preview, "http://upstream.example/graphql"),
		"query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	callAs(t, engine, upstream, "", "Bearer warm-up")
	waitForUpstreamCalls(t, upstream.authorizationRecorder, 1)

	credentials := concurrentCredentials()
	callConcurrently(t, engine, upstream, credentials)

	waitForUpstreamCalls(t, upstream.authorizationRecorder, len(credentials)+1)
	assert.ElementsMatch(t, append([]string{"Bearer warm-up"}, credentials...), upstream.values())
}

// --- Supergraph ------------------------------------------------------------------
//
// Supergraph is the only mode that turns on the data loader and single flight, see
// gqlengineadapter/adapter_supergraph.go. The entity fetch to the second subgraph runs
// through the data loader, which is a separate code path from a plain root fetch.

const (
	isolationMergedSDL = `type Query {
	allUsers: [User]
}

type User {
	id: ID!
	username: String!
	account: [BankAccount!]
}

type BankAccount {
	number: String
	balance: Float
}`

	isolationAccountsSDL = `extend type Query {
	allUsers: [User]
}

type User @key(fields: "id") {
	id: ID!
	username: String!
}`

	isolationBankAccountsSDL = `extend type User @key(fields: "id") {
	id: ID! @extends
	account: [BankAccount!]
}

type BankAccount {
	number: String
	balance: Float
}`

	isolationSupergraphOperation = "query { allUsers { id username account { number } } }"
)

// newRecordingGraphQLUpstream answers every request with responseBody and records the
// credential it carried.
func newRecordingGraphQLUpstream(t *testing.T, recorder *authorizationRecorder, responseBody string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.recordRequest(request)
		writer.Header().Set("Content-Type", "application/json")
		_, err := io.WriteString(writer, responseBody)
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	return server
}

func newSupergraphApiDefinition(accountsURL, bankAccountsURL string) *apidef.APIDefinition {
	return &apidef.APIDefinition{
		UseStandardAuth: true,
		GraphQL: apidef.GraphQLConfig{
			Enabled:       true,
			ExecutionMode: apidef.GraphQLExecutionModeSupergraph,
			Version:       apidef.GraphQLConfigVersion2,
			Schema:        isolationMergedSDL,
			Supergraph: apidef.GraphQLSupergraphConfig{
				MergedSDL: isolationMergedSDL,
				Subgraphs: []apidef.GraphQLSubgraphEntity{
					{APIID: "accounts", URL: accountsURL, SDL: isolationAccountsSDL},
					{APIID: "bank-accounts", URL: bankAccountsURL, SDL: isolationBankAccountsSDL},
				},
			},
		},
	}
}

func TestEngineV2_SupergraphIsolatesCallerAuthorization(t *testing.T) {
	accountsRecorder := newAuthorizationRecorder("")
	accounts := newRecordingGraphQLUpstream(t, accountsRecorder,
		`{"data":{"allUsers":[{"id":"1","username":"u1","__typename":"User"}]}}`)
	// The entity fetch that resolves User.account on the second subgraph.
	entitiesRecorder := newAuthorizationRecorder("")
	bankAccounts := newRecordingGraphQLUpstream(t, entitiesRecorder,
		`{"data":{"_entities":[{"account":[{"number":"123"}]}]}}`)

	engine := newIsolationEngineV2(t,
		newSupergraphApiDefinition(accounts.URL, bankAccounts.URL),
		isolationSupergraphOperation)

	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, http.DefaultTransport, "", token)
	}

	assert.Equal(t, []string{"Bearer AAA", "Bearer BBB"}, accountsRecorder.values(), "root fetch")
	assert.Equal(t, []string{"Bearer AAA", "Bearer BBB"}, entitiesRecorder.values(), "entity fetch")
}

func TestEngineV2_SupergraphUnauthenticatedCallerDoesNotInheritCredential(t *testing.T) {
	accountsRecorder := newAuthorizationRecorder("")
	accounts := newRecordingGraphQLUpstream(t, accountsRecorder,
		`{"data":{"allUsers":[{"id":"1","username":"u1","__typename":"User"}]}}`)
	entitiesRecorder := newAuthorizationRecorder("")
	bankAccounts := newRecordingGraphQLUpstream(t, entitiesRecorder,
		`{"data":{"_entities":[{"account":[{"number":"123"}]}]}}`)

	engine := newIsolationEngineV2(t,
		newSupergraphApiDefinition(accounts.URL, bankAccounts.URL),
		isolationSupergraphOperation)

	callAs(t, engine, http.DefaultTransport, "", "Bearer AAA")
	callAs(t, engine, http.DefaultTransport, "", "")

	assert.Equal(t, []string{"Bearer AAA", ""}, accountsRecorder.values(), "root fetch")
	assert.Equal(t, []string{"Bearer AAA", ""}, entitiesRecorder.values(), "entity fetch")
}

// Config version 3-preview rejects supergraph in the adapter, so there is no engine v3
// twin of the tests above. See EngineConfigV3 in apidef/adapter/graphql_config_adapter.go.
func TestNewEngineV3_RejectsSupergraph(t *testing.T) {
	apiDefinition := newSupergraphApiDefinition("http://accounts.example", "http://bank-accounts.example")
	apiDefinition.GraphQL.Version = apidef.GraphQLConfigVersion3Preview
	schema, err := graphqlv2.NewSchemaFromString(apiDefinition.GraphQL.Schema)
	require.NoError(t, err)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	engine, err := NewEngineV3(EngineV3Options{
		Logger:        logger,
		Schema:        schema,
		ApiDefinition: apiDefinition,
		HttpClient:    &http.Client{},
		Injections: EngineV3Injections{
			NewReusableBodyReadCloser: testReusableReadCloser,
		},
	})
	assert.Error(t, err)
	assert.Nil(t, engine)
}

// Credential isolation alone does not prove transport isolation: if every caller shares
// one round tripper, a shared http.Client.Transport looks identical to a request scoped
// one. Here each caller brings its own round tripper and has to be the only one that sees
// its own credential, which is what a mutated shared transport cannot deliver.
func TestEngineV2_ConcurrentCallersDoNotShareTransports(t *testing.T) {
	engine := newIsolationEngineV2(t,
		newUDGApiDefinition(apidef.GraphQLConfigVersion2, "http://upstream.example/graphql"),
		"query { hello }")

	warmUp := newAuthorizationRecordingRoundTripper()
	callAs(t, engine, warmUp, "", "Bearer warm-up")

	credentials := concurrentCredentials()
	upstreams := make([]*authorizationRecordingRoundTripper, len(credentials))
	var waitGroup sync.WaitGroup
	for i, credential := range credentials {
		upstreams[i] = newAuthorizationRecordingRoundTripper()
		waitGroup.Add(1)
		go func(i int, credential string) {
			defer waitGroup.Done()
			callAs(t, engine, upstreams[i], "", credential)
		}(i, credential)
	}
	waitGroup.Wait()

	for i, credential := range credentials {
		assert.Equal(t, []string{credential}, upstreams[i].values(),
			"the fetch of caller %d has to go through the round tripper of caller %d", i, i)
	}
}

func TestEngineV3_ConcurrentCallersDoNotShareTransports(t *testing.T) {
	engine := newIsolationEngineV3(t,
		newUDGApiDefinition(apidef.GraphQLConfigVersion3Preview, "http://upstream.example/graphql"),
		"query { hello }")

	warmUp := newAuthorizationRecordingRoundTripper()
	callAs(t, engine, warmUp, "", "Bearer warm-up")
	waitForUpstreamCalls(t, warmUp.authorizationRecorder, 1)

	credentials := concurrentCredentials()
	upstreams := make([]*authorizationRecordingRoundTripper, len(credentials))
	var waitGroup sync.WaitGroup
	for i, credential := range credentials {
		upstreams[i] = newAuthorizationRecordingRoundTripper()
		waitGroup.Add(1)
		go func(i int, credential string) {
			defer waitGroup.Done()
			callAs(t, engine, upstreams[i], "", credential)
		}(i, credential)
	}
	waitGroup.Wait()

	for i, credential := range credentials {
		waitForUpstreamCalls(t, upstreams[i].authorizationRecorder, 1)
		assert.Equal(t, []string{credential}, upstreams[i].values(),
			"the fetch of caller %d has to go through the round tripper of caller %d", i, i)
	}
}

// --- Client WebSocket upgrade path -----------------------------------------------
//
// A real subscription arrives as a WebSocket upgrade, which routes through
// handoverWebSocketConnectionToGraphQLExecutionEngine rather than the HTTP handover. That
// is the path where the context handed to the subscription handler matters: net/http
// cancels the request context as soon as ServeHTTP returns, and the gateway returns as
// soon as the connection is hijacked, so a subscription rooted at the request context
// never delivers anything. See subscriptionRequestContext.

// newWSUpgradeGateway serves the engine over a real HTTP server, so a client can perform a
// WebSocket upgrade against it the way the gateway does.
func newWSUpgradeGateway(t *testing.T, engine Engine) string {
	t.Helper()
	upgrader := &gorillawebsocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _, err := engine.HandleReverseProxy(ReverseProxyParams{
			RoundTripper:       http.DefaultTransport,
			ResponseWriter:     writer,
			OutRequest:         request,
			WebSocketUpgrader:  upgrader,
			NeedsEngine:        true,
			IsWebSocketUpgrade: true,
		})
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	return "ws" + strings.TrimPrefix(server.URL, "http")
}

// subscribeOverWebSocket opens a graphql-ws subscription against the gateway and returns
// the first payload message. It fails the test if the connection dies before one arrives.
func subscribeOverWebSocket(t *testing.T, gatewayURL, headerName, credential, operation string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	requestHeader := http.Header{}
	if credential != "" {
		if headerName == "" {
			headerName = "Authorization"
		}
		requestHeader.Set(headerName, credential)
	}
	connection, _, err := nhooyrwebsocket.Dial(ctx, gatewayURL, &nhooyrwebsocket.DialOptions{
		Subprotocols: []string{protocolGraphQLWS},
		HTTPHeader:   requestHeader,
	})
	require.NoError(t, err)
	defer closeWSConnection(t, connection)

	require.NoError(t, connection.Write(ctx, nhooyrwebsocket.MessageText, []byte(`{"type":"connection_init"}`)))
	_, acknowledgement, err := connection.Read(ctx)
	require.NoError(t, err)
	require.Contains(t, string(acknowledgement), "connection_ack")

	start := fmt.Sprintf(`{"id":"1","type":"start","payload":{"query":%q}}`, operation)
	require.NoError(t, connection.Write(ctx, nhooyrwebsocket.MessageText, []byte(start)))

	for {
		_, message, err := connection.Read(ctx)
		require.NoError(t, err, "the subscription closed before it delivered a payload")
		// Skip keep alives, which carry no payload.
		if strings.Contains(string(message), `"payload"`) {
			return string(message)
		}
	}
}

func TestEngineV2_WebSocketUpgradeDeliversSubscriptionData(t *testing.T) {
	upstream := newAuthorizationRecorder("")
	server := newRecordingWSUpstream(t, upstream, protocolGraphQLWS, messageTypeData)
	engine := newIsolationEngineV2(t,
		newUDGSubscriptionApiDefinition(t, apidef.GraphQLConfigVersion2, apidef.GQLSubscriptionWS, server.URL),
		"subscription { count }")

	message := subscribeOverWebSocket(t, newWSUpgradeGateway(t, engine), "", "Bearer AAA", "subscription { count }")

	assert.Contains(t, message, `"count":1`)
	assert.Equal(t, []string{"Bearer AAA"}, upstream.values())
}

func TestEngineV2_WebSocketUpgradeIsolatesCallerAuthorization(t *testing.T) {
	upstream := newAuthorizationRecorder("")
	server := newRecordingWSUpstream(t, upstream, protocolGraphQLWS, messageTypeData)
	engine := newIsolationEngineV2(t,
		newUDGSubscriptionApiDefinition(t, apidef.GraphQLConfigVersion2, apidef.GQLSubscriptionWS, server.URL),
		"subscription { count }")
	gateway := newWSUpgradeGateway(t, engine)

	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		message := subscribeOverWebSocket(t, gateway, "", token, "subscription { count }")
		assert.Contains(t, message, `"count":1`)
	}

	assert.Equal(t, []string{"Bearer AAA", "Bearer BBB"}, upstream.values())
}

// --- Dynamic upstream headers ----------------------------------------------------
//
// A UDG global header of $tyk_context.headers_Authorization is how an API definition asks
// for the caller's credential to be forwarded upstream, and it is the shape where an
// unresolved value does the most damage. The header modifier is what resolves it, and it has
// to, because the library applies the modifier before it derives the key that decides whether
// two callers share one upstream subscription connection: connectionKey in the v1
// subscription client, UniqueRequestID in the v2 resolver. A value still holding the literal
// $tyk_context token is the same for every caller, so every caller hashes alike.

const dynamicUpstreamHeader = "X-Upstream-Authorization"

// newDynamicHeaderUDGApiDefinition builds a UDG API whose only upstream credential is a
// dynamic global header. StripAuthData keeps propagateAuthHeaders out of it, so a concrete
// per caller value cannot reach the upstream by any other route.
func newDynamicHeaderUDGApiDefinition(version apidef.GraphQLConfigVersion, upstreamURL string) *apidef.APIDefinition {
	apiDefinition := newUDGApiDefinition(version, upstreamURL)
	apiDefinition.StripAuthData = true
	apiDefinition.GraphQL.Engine.GlobalHeaders = []apidef.UDGGlobalHeader{{
		Key:   dynamicUpstreamHeader,
		Value: "$tyk_context.headers_Authorization",
	}}
	return apiDefinition
}

// newDynamicHeaderUDGSubscriptionApiDefinition is the same thing for a subscription served by
// a GraphQL data source.
func newDynamicHeaderUDGSubscriptionApiDefinition(t *testing.T, version apidef.GraphQLConfigVersion, subscriptionType apidef.SubscriptionType, upstreamURL string) *apidef.APIDefinition {
	t.Helper()
	apiDefinition := newUDGSubscriptionApiDefinition(t, version, subscriptionType, upstreamURL)
	apiDefinition.StripAuthData = true
	apiDefinition.GraphQL.Engine.GlobalHeaders = []apidef.UDGGlobalHeader{{
		Key:   dynamicUpstreamHeader,
		Value: "$tyk_context.headers_Authorization",
	}}
	return apiDefinition
}

func TestEngineV2_DynamicUpstreamHeaderIsolatesCallerCredential(t *testing.T) {
	engine := newIsolationEngineV2(t,
		newDynamicHeaderUDGApiDefinition(apidef.GraphQLConfigVersion2, "http://upstream.example/graphql"),
		"query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, upstream, "", token)
	}

	assert.Equal(t, []string{"Bearer AAA", "Bearer BBB"}, upstream.headerValues(dynamicUpstreamHeader))
}

func TestEngineV3_DynamicUpstreamHeaderIsolatesCallerCredential(t *testing.T) {
	engine := newIsolationEngineV3(t,
		newDynamicHeaderUDGApiDefinition(apidef.GraphQLConfigVersion3Preview, "http://upstream.example/graphql"),
		"query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	for _, token := range []string{"Bearer AAA", "Bearer BBB"} {
		callAs(t, engine, upstream, "", token)
	}

	waitForUpstreamCalls(t, upstream.authorizationRecorder, 2)
	assert.ElementsMatch(t, []string{"Bearer AAA", "Bearer BBB"}, upstream.headerValues(dynamicUpstreamHeader))
}

// The leak in one test. Every caller brings a different credential, and the count of upstream
// connections is the assertion: an unresolved header value makes all twenty connection keys
// identical, and the library dials and registers under one lock, so the nineteen callers
// behind the first one deterministically multiplex onto its connection. Twenty distinct
// credentials upstream therefore means twenty connections, none of them shared.
func TestEngineV2_DynamicUpstreamHeaderDoesNotShareSubscriptionConnection(t *testing.T) {
	upstream := newAuthorizationRecorder(dynamicUpstreamHeader)
	server := newRecordingWSUpstream(t, upstream, protocolGraphQLWS, messageTypeData)
	engine := newIsolationEngineV2(t,
		newDynamicHeaderUDGSubscriptionApiDefinition(t, apidef.GraphQLConfigVersion2, apidef.GQLSubscriptionWS, server.URL),
		"subscription { count }")

	credentials := concurrentCredentials()
	callConcurrently(t, engine, http.DefaultTransport, credentials)

	assert.ElementsMatch(t, credentials, upstream.values(),
		"every caller has to open its own upstream connection with its own credential")
}

func TestEngineV3_DynamicUpstreamHeaderDoesNotShareSubscriptionConnection(t *testing.T) {
	upstream := newAuthorizationRecorder(dynamicUpstreamHeader)
	server := newRecordingWSUpstream(t, upstream, protocolGraphQLWS, messageTypeData)
	engine := newIsolationEngineV3(t,
		newDynamicHeaderUDGSubscriptionApiDefinition(t, apidef.GraphQLConfigVersion3Preview, apidef.GQLSubscriptionWS, server.URL),
		"subscription { count }")

	credentials := concurrentCredentials()
	callConcurrently(t, engine, http.DefaultTransport, credentials)

	waitForUpstreamCalls(t, upstream, len(credentials))
	assert.ElementsMatch(t, credentials, upstream.values(),
		"every caller has to open its own upstream connection with its own credential")
}

// The plain fetch path under the same load, to catch a replacer that reads the wrong request
// when several are in flight. Cold, so nothing is cached when the burst starts.
func TestEngineV2_ConcurrentDynamicHeaderCallersDoNotShareCredentials(t *testing.T) {
	engine := newIsolationEngineV2(t,
		newDynamicHeaderUDGApiDefinition(apidef.GraphQLConfigVersion2, "http://upstream.example/graphql"),
		"query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	credentials := concurrentCredentials()
	callConcurrently(t, engine, upstream, credentials)

	assert.ElementsMatch(t, credentials, upstream.headerValues(dynamicUpstreamHeader))
}

func TestEngineV3_ConcurrentDynamicHeaderCallersDoNotShareCredentials(t *testing.T) {
	engine := newIsolationEngineV3(t,
		newDynamicHeaderUDGApiDefinition(apidef.GraphQLConfigVersion3Preview, "http://upstream.example/graphql"),
		"query { hello }")

	upstream := newAuthorizationRecordingRoundTripper()
	credentials := concurrentCredentials()
	callConcurrently(t, engine, upstream, credentials)

	waitForUpstreamCalls(t, upstream.authorizationRecorder, len(credentials))
	assert.ElementsMatch(t, credentials, upstream.headerValues(dynamicUpstreamHeader))
}

// Engine v3 has no WebSocket upgrade test. 3-preview accepts the upgrade and starts the
// upstream subscription with the right credential, but never writes a payload back to the
// client. That is independent of the subscription context: it behaves identically with
// context.Background(), with the request context and with the engine context. The v3
// upstream credential isolation is covered through the HTTP handover instead, see
// TestEngineV3_WebSocketSubscriptionIsolatesCallerAuthorization.
