package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef/mcp/catalogue"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/mcp/tooloverride"
)

// remoteMCPCatalogueTimeout bounds the whole catalogue check of one API load.
var remoteMCPCatalogueTimeout = 10 * time.Second

var (
	errRemoteMCPToolViewSpecUnloaded = errors.New("API unloaded")
	errRemoteMCPToolViewSuperseded   = errors.New("superseded by a newer catalogue check")
)

// remoteMCPToolViewState tracks the background catalogue check of a remote
// MCP tool view. generation identifies the latest check; a check may only log
// while it is still the latest one, so a superseded or unloaded check never
// reports on a newer configuration.
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

// isLatestRemoteMCPToolViewCheck reports whether generation is still the
// latest catalogue check of the spec.
func (s *APISpec) isLatestRemoteMCPToolViewCheck(generation uint64) bool {
	state := &s.mcpToolViewState
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.generation == generation
}

// loadRemoteMCPToolView compiles a remote MCP proxy's x-tyk-mcp-server tool
// overrides and admits them immediately. Invalid configurations were already
// rejected by static validation; a configuration that still fails to compile
// is not applied.
//
// The upstream catalogue is then checked in the background, only to report
// problems; the check never changes the admitted view and never blocks
// loading. It warns when an override sets the name of an upstream tool that
// has no override, when an override's source tool is not in the catalogue,
// and when the catalogue cannot be listed.
//
// Fetch scope: the check calls Proxy.TargetURL directly, sending only static
// upstream basic auth (see remoteMCPCatalogueHeader). It does not use load
// balancing, service discovery, the egress proxy, upstream mTLS certificates,
// request header transforms or other upstream auth, and it does not follow
// redirects. APIs that depend on those get the "could not list" warning.
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
	spec.mcpToolView.Store(view)

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
		if !spec.isLatestRemoteMCPToolViewCheck(generation) {
			return
		}
		if err != nil {
			logger.WithError(err).Warning("Could not list the upstream MCP tool catalogue to check tool overrides; applying them unchecked")
			return
		}

		missing, collisions := oas.InspectRemoteMCPToolCatalogue(ext, names)
		for _, collision := range collisions {
			logger.WithFields(logrus.Fields{"exposed_name": collision.Name, "source_tool": collision.Source}).
				Warning("MCP tool override sets a name that an upstream tool without an override already has")
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
	out, changed, missing, err := view.RewriteToolsList(body, isFirstToolsListPage(state))
	now := time.Now()
	if err != nil {
		if spec.mcpResponseWarnings.due("rewrite", now) {
			logger.WithError(err).Warning("Upstream tools/list response was not rewritten with MCP tool overrides; it is passed through unchanged")
		}
		return body, false
	}
	for _, source := range missing {
		if view.ShouldWarnMissing(source, now) {
			logger.WithField("source_tool", source).Warning("MCP tool override source tool is not in the upstream tool list; it is not exposed")
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
