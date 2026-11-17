package gateway

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp/tooloverride"
	"github.com/TykTechnologies/tyk/user"
)

// encodeFakeBody compresses payload the way an upstream that honours
// Accept-Encoding would. "br" is not compressed: the gateway has no brotli
// decoder, so its bytes only need to be opaque.
func encodeFakeBody(t *testing.T, encoding string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	switch encoding {
	case "gzip":
		zw := gzip.NewWriter(&buf)
		_, err := zw.Write(payload)
		require.NoError(t, err)
		require.NoError(t, zw.Close())
	case "deflate":
		zw := zlib.NewWriter(&buf)
		_, err := zw.Write(payload)
		require.NoError(t, err)
		require.NoError(t, zw.Close())
	case "br":
		buf.WriteString("\x0b\x02opaque-brotli-bytes")
	default:
		t.Fatalf("unsupported fake encoding %q", encoding)
	}
	return buf.Bytes()
}

// compressedMCPResponse is a response read by a client that accepts
// compressed bodies, like MCP SDK clients do.
type compressedMCPResponse struct {
	status   int
	header   http.Header
	raw      []byte // bytes on the wire
	encoding string // Content-Encoding the client received
	body     []byte // the JSON-RPC response, decoded and unwrapped from SSE
}

func remoteMCPCompressedRequest(t *testing.T, ts *Test, key, method, params string) compressedMCPResponse {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":11,"method":"` + method + `","params":` + params + `}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+remoteMCPListenPath, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	// br first: clients such as Node's fetch offer br, and servers that
	// prefer it answer with it.
	req.Header.Set("Accept-Encoding", "br, gzip, deflate")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if key != "" {
		req.Header.Set("Authorization", key)
	}
	// Setting Accept-Encoding by hand turns off the transport's transparent
	// decompression, so the test sees exactly what the gateway sent.
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	out := compressedMCPResponse{status: res.StatusCode, header: res.Header, raw: raw, encoding: res.Header.Get("Content-Encoding")}
	decoded := raw
	switch out.encoding {
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		require.NoError(t, err)
		decoded, err = io.ReadAll(zr)
		require.NoError(t, err)
	case "deflate":
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		require.NoError(t, err)
		decoded, err = io.ReadAll(zr)
		require.NoError(t, err)
	case "":
	default:
		out.body = raw
		return out
	}
	out.body = decoded
	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		for _, line := range strings.Split(string(decoded), "\n") {
			if data, ok := strings.CutPrefix(line, "data: "); ok && strings.Contains(data, `"id":11`) {
				out.body = []byte(data)
				return out
			}
		}
		t.Fatalf("no response event in stream: %q", decoded)
	}
	return out
}

func TestRemoteMCPToolView_CompressedUpstream(t *testing.T) {
	for _, encoding := range []string{"gzip", "deflate"} {
		for _, transport := range []string{"json", "sse"} {
			t.Run(encoding+"/"+transport, func(t *testing.T) {
				ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-"+encoding+"-"+transport, transport == "sse", githubToolOverrides(),
					upstreamDeleteRepo, upstreamCreateIssue, upstreamListRepos)
				fake.mu.Lock()
				fake.encoding = encoding
				fake.mu.Unlock()

				res := remoteMCPCompressedRequest(t, ts, "", "tools/list", `{}`)
				require.Equal(t, http.StatusOK, res.status, string(res.raw))
				tools, names, _ := listedTools(t, res.body)
				assert.Equal(t, []string{"delete_repo", "create_issue", "list_repos"}, names)
				assert.JSONEq(t, `{"destructiveHint":true}`, extractAnnotations(t, tools["delete_repo"]), "the overrides must reach the client")
				assert.JSONEq(t, upstreamListRepos, string(tools["list_repos"]))
				if transport == "json" {
					assert.Empty(t, res.encoding, "an edited body is sent decoded")
					assert.Equal(t, strconv.Itoa(len(res.raw)), res.header.Get("Content-Length"))
				}

				call := remoteMCPCompressedRequest(t, ts, "", "tools/call", `{"name":"delete_repo","arguments":{"repo":"tyk"}}`)
				require.Equal(t, http.StatusOK, call.status, string(call.raw))
				assert.Contains(t, string(call.body), "called delete_repo")
				fake.mu.Lock()
				defer fake.mu.Unlock()
				assert.Equal(t, []string{"delete_repo"}, fake.calls)
			})
		}
	}

	t.Run("an unedited compressed body passes through compressed", func(t *testing.T) {
		ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-gzip-unedited", false, githubToolOverrides(), upstreamListRepos)
		fake.mu.Lock()
		fake.encoding = "gzip"
		fake.mu.Unlock()

		res := remoteMCPCompressedRequest(t, ts, "", "tools/list", `{}`)
		require.Equal(t, http.StatusOK, res.status)
		assert.Equal(t, "gzip", res.encoding)
		tools, _, _ := listedTools(t, res.body)
		assert.JSONEq(t, upstreamListRepos, string(tools["list_repos"]))
	})

	t.Run("an encoding the gateway cannot decode passes through with a rate-limited warning", func(t *testing.T) {
		const apiID = "remote-mcp-br"
		ts, fake, _ := startRemoteMCPProxyWithView(t, apiID, false, githubToolOverrides(), upstreamDeleteRepo)
		logs := recordRemoteMCPLogs(t, apiID)
		fake.mu.Lock()
		fake.encoding = "br"
		fake.mu.Unlock()

		for range 3 {
			res := remoteMCPCompressedRequest(t, ts, "", "tools/list", `{}`)
			require.Equal(t, http.StatusOK, res.status)
			assert.Equal(t, "br", res.encoding)
			assert.Equal(t, encodeFakeBody(t, "br", nil), res.raw, "the body is passed through unchanged")
		}
		assert.Equal(t, 1, logs.count(logrus.WarnLevel, "br"), "one warning about the undecodable encoding")
	})
}

func TestMCPListFilter_CompressedUpstreamAppliesAccessRules(t *testing.T) {
	for _, transport := range []string{"json", "sse"} {
		t.Run(transport, func(t *testing.T) {
			ts := StartTest(nil)
			t.Cleanup(ts.Close)
			const apiID = "remote-mcp-gzip-acl"
			fake, upstream := newFakeRemoteMCPServer(t, upstreamDeleteRepo, upstreamListRepos)
			fake.encoding = "gzip"
			fake.sse = transport == "sse"
			spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, nil, func(spec *APISpec) {
				spec.UseKeylessAccess = false
			})
			policyID := ts.CreatePolicy(func(p *user.Policy) {
				p.AccessRights = map[string]user.AccessDefinition{spec.APIID: {
					APIID:           spec.APIID,
					MCPAccessRights: user.MCPAccessRights{Tools: user.AccessControlRules{Blocked: []string{"delete_repo"}}},
				}}
			})
			_, key := ts.CreateSession(func(s *user.SessionState) { s.ApplyPolicies = []string{policyID} })

			res := remoteMCPCompressedRequest(t, ts, key, "tools/list", `{}`)
			require.Equal(t, http.StatusOK, res.status, string(res.raw))
			_, names, _ := listedTools(t, res.body)
			assert.Equal(t, []string{"list_repos"}, names, "a blocked tool must not be listed")
		})
	}
}

func TestMCPListFilterResponseHandler_RewriteFailureIsAWarning(t *testing.T) {
	const apiID = "remote-mcp-rewrite-failure"
	logs := recordRemoteMCPLogs(t, apiID)
	view, err := tooloverride.Compile(&oas.TykMCPServer{Primitives: githubToolOverrides()})
	require.NoError(t, err)
	h := buildMCPListFilterHandler(apiID, true)
	h.Spec.APIDefinition.Name = "rewrite-failure"
	h.Spec.mcpToolView.Store(view)

	const malformed = `{"jsonrpc":"2.0","id":1,"result":{"tools":"not-a-list"}}`
	for range 3 {
		req, err := http.NewRequest(http.MethodPost, "/", nil)
		require.NoError(t, err)
		httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{Method: "tools/list", ID: float64(1)})
		res := makeHTTPResponse([]byte(malformed))
		require.NoError(t, h.HandleResponse(nil, res, req, &user.SessionState{}))
		assert.Equal(t, malformed, string(readResponseBody(t, res)), "a body that cannot be rewritten passes through")
	}
	assert.Equal(t, 1, logs.count(logrus.WarnLevel, "not rewritten"), "the failure is a rate-limited warning")
}

// negotiatedFakeEncoding returns the first encoding in acceptEncoding that
// the fake upstream can produce, or "" for an uncompressed response.
func negotiatedFakeEncoding(acceptEncoding string) string {
	for _, part := range strings.Split(acceptEncoding, ",") {
		token := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		switch token {
		case "br", "gzip", "deflate":
			return token
		}
	}
	return ""
}

func TestRemoteMCPToolView_BrPreferringClient(t *testing.T) {
	for _, transport := range []string{"json", "sse"} {
		t.Run(transport, func(t *testing.T) {
			ts, fake, _ := startRemoteMCPProxyWithView(t, "remote-mcp-br-client-"+transport, transport == "sse", githubToolOverrides(),
				upstreamDeleteRepo, upstreamListRepos)
			fake.mu.Lock()
			fake.encoding = "negotiate"
			fake.mu.Unlock()

			// remoteMCPCompressedRequest offers "br, gzip, deflate".
			res := remoteMCPCompressedRequest(t, ts, "", "tools/list", `{}`)
			require.Equal(t, http.StatusOK, res.status, string(res.raw))
			assert.NotEqual(t, "br", res.encoding)
			tools, _, _ := listedTools(t, res.body)
			assert.JSONEq(t, `{"destructiveHint":true}`, extractAnnotations(t, tools["delete_repo"]), "the overrides must reach a client that offers br")
		})
	}
}

func TestMCPListFilterResponseHandler_DecodedSizeIsBoundedByDefault(t *testing.T) {
	// 33 MiB of zeros compresses to about 33 KiB.
	bomb := encodeFakeBody(t, "gzip", make([]byte, 33<<20))
	view, err := tooloverride.Compile(&oas.TykMCPServer{Primitives: githubToolOverrides()})
	require.NoError(t, err)

	for _, method := range []string{"tools/list", "server/discover"} {
		t.Run(method, func(t *testing.T) {
			apiID := "remote-mcp-bomb-" + strings.ReplaceAll(method, "/", "-")
			logs := recordRemoteMCPLogs(t, apiID)
			h := buildMCPListFilterHandler(apiID, true)
			h.Spec.mcpToolView.Store(view)
			require.Nil(t, h.Gw, "no gateway config: MaxResponseBodySize is 0")

			req, err := http.NewRequest(http.MethodPost, "/", nil)
			require.NoError(t, err)
			httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{Method: method, ID: float64(1)})
			res := makeHTTPResponse(bomb)
			res.Header.Set("Content-Encoding", "gzip")
			require.NoError(t, h.HandleResponse(nil, res, req, &user.SessionState{}))

			if method == "server/discover" {
				assert.Equal(t, http.StatusBadGateway, res.StatusCode, "discovery fails closed")
			} else {
				assert.Equal(t, bomb, readResponseBody(t, res), "the body passes through unchanged")
				assert.Equal(t, "gzip", res.Header.Get("Content-Encoding"))
			}
			assert.NotNil(t, logs.find(logrus.WarnLevel, "could not be decoded", "exceeds"))
		})
	}
}

func TestMCPListFilterResponseHandler_EditedBodiesDropValidators(t *testing.T) {
	h := buildMCPListFilterHandlerWithMiddleware("remote-mcp-etag", &oas.Middleware{McpTools: oas.MCPPrimitives{
		"delete_repo": {Operation: oas.Operation{Block: &oas.Allowance{Enabled: true}}},
	}})
	for _, encoding := range []string{"", "gzip"} {
		t.Run("encoding="+encoding, func(t *testing.T) {
			body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[` + upstreamDeleteRepo + `,` + upstreamListRepos + `]}}`)
			req, err := http.NewRequest(http.MethodPost, "/", nil)
			require.NoError(t, err)
			httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{Method: "tools/list", ID: float64(1)})
			res := makeHTTPResponse(body)
			if encoding != "" {
				res = makeHTTPResponse(encodeFakeBody(t, encoding, body))
				res.Header.Set("Content-Encoding", encoding)
			}
			res.Header.Set("ETag", `"upstream"`)
			res.Header.Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
			require.NoError(t, h.HandleResponse(nil, res, req, &user.SessionState{}))

			assert.Equal(t, []string{"list_repos"}, extractToolNames(t, readResponseBody(t, res)), "control: the body was edited")
			assert.Empty(t, res.Header.Get("ETag"), "an edited body has a different entity tag")
			assert.Empty(t, res.Header.Get("Last-Modified"))
			assert.Empty(t, res.Header.Get("Content-Encoding"))
		})
	}
}

func TestMCPEventStream_DebugLoggingKeepsTheUpstreamEncoding(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	// After StartTest, which applies the configured log level.
	log.SetTestLogLevel(t, logrus.DebugLevel)
	fake, upstream := newFakeRemoteMCPServer(t, upstreamDeleteRepo)
	fake.sse = true
	fake.encoding = "gzip"
	spec := loadRemoteMCPProxy(t, ts, "remote-mcp-debug-sse", upstream.URL, nil)
	require.Nil(t, spec.MCPToolView())

	res := remoteMCPCompressedRequest(t, ts, "", "tools/call", `{"name":"delete_repo","arguments":{}}`)
	require.Equal(t, http.StatusOK, res.status, string(res.raw))
	assert.Equal(t, "gzip", res.encoding, "only filtering hooks decode the stream; the debug logging hook does not")
	assert.Contains(t, string(res.body), "called delete_repo")
}
