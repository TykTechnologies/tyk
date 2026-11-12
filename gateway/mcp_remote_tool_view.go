package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef/mcp/catalogue"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/httputil"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/mcp/tooloverride"
)

// remoteMCPCatalogueTimeout bounds the whole catalogue check of one API load.
var remoteMCPCatalogueTimeout = 10 * time.Second

var (
	errRemoteMCPToolViewSpecUnloaded = errors.New("API unloaded")
	errRemoteMCPToolViewSuperseded   = errors.New("superseded by a newer catalogue check")
)

// remoteMCPToolViewState is the per-spec admission state of a remote MCP tool
// view. generation identifies the latest catalogue check; a check may only
// admit its view while it is still the latest one, so a superseded or
// unloaded check can never overwrite a newer decision.
type remoteMCPToolViewState struct {
	mu         sync.Mutex
	generation uint64
	cancel     context.CancelCauseFunc
	unloadHook bool
	// checkDone is closed when the latest catalogue check finishes. Only
	// tests wait on it; production code never blocks on a check.
	checkDone chan struct{}
}

// MCPToolView returns the admitted remote MCP tool view, or nil.
func (s *APISpec) MCPToolView() *tooloverride.View {
	return s.mcpToolView.Load()
}

func (s *APISpec) remoteMCPToolViewCheckDone() <-chan struct{} {
	s.mcpToolViewState.mu.Lock()
	defer s.mcpToolViewState.mu.Unlock()
	return s.mcpToolViewState.checkDone
}

// startRemoteMCPToolViewCheck cancels any check still running for this spec
// and returns the context and generation of a new one.
func (s *APISpec) startRemoteMCPToolViewCheck(parent context.Context) (context.Context, uint64, chan struct{}) {
	state := &s.mcpToolViewState
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.cancel != nil {
		state.cancel(errRemoteMCPToolViewSuperseded)
	}
	ctx, cancel := context.WithCancelCause(parent)
	state.cancel = cancel
	state.generation++
	state.checkDone = make(chan struct{})
	if !state.unloadHook {
		state.unloadHook = true
		s.AddUnloadHook(s.stopRemoteMCPToolViewCheck)
	}
	return ctx, state.generation, state.checkDone
}

func (s *APISpec) stopRemoteMCPToolViewCheck() {
	state := &s.mcpToolViewState
	state.mu.Lock()
	defer state.mu.Unlock()
	state.generation++
	if state.cancel != nil {
		state.cancel(errRemoteMCPToolViewSpecUnloaded)
		state.cancel = nil
	}
}

// admitRemoteMCPToolView stores view if generation is still the latest check.
func (s *APISpec) admitRemoteMCPToolView(generation uint64, view *tooloverride.View) bool {
	state := &s.mcpToolViewState
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.generation != generation {
		return false
	}
	s.mcpToolView.Store(view)
	return true
}

// loadRemoteMCPToolView compiles a remote MCP proxy's x-tyk-mcp-server tool
// overrides and admits them once the upstream catalogue has been checked.
//
// Overrides can rename tools, so a view is only admitted after a check that no
// final name collides with an upstream tool that has no override. The check
// needs the upstream catalogue, so it runs in the background and never blocks
// loading. Until it finishes, and when it finds a collision, the API keeps
// serving the view admitted for the spec it replaces (none for a new API).
// When the upstream cannot be listed, the view is admitted unchecked, because
// the configuration was already validated and the upstream may only be
// temporarily unreachable.
//
// Fetch scope: the check calls Proxy.TargetURL directly, sending only static
// upstream basic auth (see remoteMCPCatalogueHeader). It does not use load
// balancing, service discovery, the egress proxy, upstream mTLS certificates,
// request header transforms or other upstream auth, and it does not follow
// redirects. APIs that depend on those get the "applying them unchecked"
// warning.
func (gw *Gateway) loadRemoteMCPToolView(spec *APISpec, logger *logrus.Entry) {
	if !spec.IsOAS || !spec.IsMCP() || spec.IsPairedMCPAdapterProxy() {
		return
	}
	ext := spec.OAS.GetTykMCPServerExtension()
	view, err := tooloverride.Compile(ext)
	if err != nil {
		logger.WithError(err).Error("MCP tool overrides are invalid and are not applied")
		return
	}
	if view == nil {
		return
	}

	// When the replaced spec's own check is still pending, its admitted view
	// is nil, so the new spec also starts without overrides.
	if previous := gw.getApiSpec(spec.APIID); previous != nil && previous != spec {
		spec.mcpToolView.Store(previous.MCPToolView())
	}

	ctx, generation, done := spec.startRemoteMCPToolViewCheck(gw.ctx)
	client := gw.remoteMCPCatalogueClient(spec)
	requestHeader := remoteMCPCatalogueHeader(spec)
	targetURL := spec.Proxy.TargetURL

	go func() {
		defer close(done)
		defer client.CloseIdleConnections()

		checkCtx, cancelCheck := context.WithTimeout(ctx, remoteMCPCatalogueTimeout)
		defer cancelCheck()
		names, err := catalogue.FetchToolNames(checkCtx, client, targetURL, requestHeader)
		if cause := context.Cause(ctx); errors.Is(cause, errRemoteMCPToolViewSpecUnloaded) || errors.Is(cause, errRemoteMCPToolViewSuperseded) {
			return
		}
		if err != nil {
			if spec.admitRemoteMCPToolView(generation, view) {
				logger.WithError(err).Warning("Could not list the upstream MCP tool catalogue to check tool overrides; applying them unchecked")
			}
			return
		}

		missing, err := oas.CheckRemoteMCPToolCatalogue(ext, names)
		if err != nil {
			logger.WithError(err).Error("MCP tool overrides are not applied; keeping the previously applied tool overrides")
			return
		}
		if !spec.admitRemoteMCPToolView(generation, view) {
			return
		}
		for _, source := range missing {
			logger.WithField("source_tool", source).Warning("MCP tool override source tool is not in the upstream tool list; it is not exposed")
		}
	}()
}

// remoteMCPCatalogueHeader returns the upstream credentials the catalogue
// check can send without a client request: static upstream basic auth.
// Upstream OAuth, request signing and credentials forwarded from the client
// are not available here; such upstreams usually reject the check, which is
// then treated like an unreachable upstream.
func remoteMCPCatalogueHeader(spec *APISpec) http.Header {
	auth := spec.UpstreamAuth
	if !auth.IsEnabled() || !auth.BasicAuth.Enabled {
		return nil
	}
	name := header.Authorization
	if custom := auth.BasicAuth.Header.AuthKeyName(); auth.BasicAuth.Header.Enabled && custom != "" {
		name = custom
	}
	h := http.Header{}
	h.Set(name, httputil.AuthHeader(auth.BasicAuth.Username, auth.BasicAuth.Password))
	return h
}

// remoteMCPCatalogueClient never follows redirects, so the upstream
// credential cannot be sent to another host and the check cannot be steered
// to other addresses; a 3xx is handled like an unreachable upstream.
func (gw *Gateway) remoteMCPCatalogueClient(spec *APISpec) *http.Client {
	// http.DefaultTransport is replaceable; start from its settings only when
	// it is still a *http.Transport.
	var transport *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = base.Clone()
	} else {
		transport = &http.Transport{}
	}
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: gw.GetConfig().ProxySSLInsecureSkipVerify || spec.Proxy.Transport.SSLInsecureSkipVerify, //nolint:gosec // mirrors the proxy's own upstream TLS setting
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       remoteMCPCatalogueTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// remoteMCPToolsListView returns the admitted tool view when the request is a
// tools/list on a remote MCP proxy that has one.
func remoteMCPToolsListView(spec *APISpec, state *httpctx.JSONRPCRoutingState) *tooloverride.View {
	if spec == nil || state == nil || state.Method != mcp.MethodToolsList {
		return nil
	}
	return spec.MCPToolView()
}

// rewriteRemoteMCPToolsList applies view to a tools/list response body. A
// body that cannot be rewritten is passed through unchanged.
func rewriteRemoteMCPToolsList(spec *APISpec, view *tooloverride.View, state *httpctx.JSONRPCRoutingState, body []byte, logger *logrus.Entry) ([]byte, bool) {
	logger = logger.WithFields(logrus.Fields{"api_id": spec.APIID, "api_name": spec.Name})
	out, changed, drift, err := view.RewriteToolsList(body, isFirstToolsListPage(state))
	if err != nil {
		logger.WithError(err).Debug("Upstream tools/list response was not rewritten with MCP tool overrides")
		return body, false
	}
	now := time.Now()
	for _, source := range drift.Missing {
		if view.ShouldWarnMissing(source, now) {
			logger.WithField("source_tool", source).Warning("MCP tool override source tool is not in the upstream tool list; it is not exposed")
		}
	}
	for _, name := range drift.Hidden {
		if view.ShouldWarnHidden(name, now) {
			logger.WithField("upstream_tool", name).Warning("Upstream MCP tool has the name of a tool override and is hidden; the override is exposed under that name")
		}
	}
	return out, changed
}

func isFirstToolsListPage(state *httpctx.JSONRPCRoutingState) bool {
	var params struct {
		Cursor *string `json:"cursor"`
	}
	if len(state.Params) > 0 && json.Unmarshal(state.Params, &params) != nil {
		return false
	}
	return params.Cursor == nil
}

// remoteMCPToolViewBypassesCache keeps the response cache away from
// tools/list and tools/call while a tool view is active, so entries stored
// before the view changed are never replayed.
func remoteMCPToolViewBypassesCache(spec *APISpec, r *http.Request) bool {
	if spec == nil || r == nil || spec.MCPToolView() == nil {
		return false
	}
	state := httpctx.GetJSONRPCRoutingState(r)
	return state != nil && (state.Method == mcp.MethodToolsList || state.Method == mcp.MethodToolsCall)
}

// dispatchRemoteMCPToolsCall maps a tools/call for an exposed tool name back
// to the upstream tool on a remote MCP proxy with a tool view. It runs at
// final dispatch, after authentication, access rules and rate limits have
// been applied to the exposed name, and leaves the routing state, analytics
// and the response untouched.
//
// A call naming an upstream tool that an override renamed away, and that is
// not bound to another override, is answered with the JSON-RPC error the MCP
// SDK returns for an unknown tool and never reaches the upstream. It reports
// whether it wrote a response.
func dispatchRemoteMCPToolsCall(w http.ResponseWriter, r *http.Request, spec *APISpec, state *httpctx.JSONRPCRoutingState) (bool, error) {
	if state.Method != mcp.MethodToolsCall {
		return false, nil
	}
	view := spec.MCPToolView()
	if view == nil {
		return false, nil
	}

	exposed := state.PrimitiveName
	upstream, known := view.ResolveCall(exposed)
	if !known {
		writeMCPUnknownTool(w, r, state, exposed)
		return true, nil
	}

	// Mcp-Name mirrors params.name. A legacy request may send one that does
	// not match its body, so every allowed call carries the name of the tool
	// it is dispatched to, in the encoding the client chose.
	if values := r.Header.Values(mcp.HeaderName); len(values) > 0 {
		mirrored := make([]string, len(values))
		for i, value := range values {
			mirrored[i] = mcp.EncodeMirroredHeaderLike(value, upstream)
		}
		r.Header[http.CanonicalHeaderKey(mcp.HeaderName)] = mirrored
	}
	if upstream == exposed {
		return false, nil
	}

	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		return false, err
	}
	body, err = tooloverride.TranslateToolsCall(body, exposed, upstream)
	if err != nil {
		return false, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set(httpHeaderContentLength, strconv.Itoa(len(body)))
	return false, nil
}

func writeMCPUnknownTool(w http.ResponseWriter, r *http.Request, state *httpctx.JSONRPCRoutingState, name string) {
	message := fmt.Sprintf("unknown tool %q", name)
	ctxSetJSONRPCErrorCode(r, int64(mcp.JSONRPCInvalidParams))
	if ingress := httpctx.GetMCPProtocolContext(r); ingress != nil {
		ingress.Validation = mcp.ProtocolValidation{Checked: true, Code: mcp.JSONRPCInvalidParams, Message: message, HTTPStatus: http.StatusBadRequest}
	}
	jsonrpcerrors.WriteJSONRPCErrorWithCode(w, state.ID, http.StatusBadRequest, mcp.JSONRPCInvalidParams, message)
}
