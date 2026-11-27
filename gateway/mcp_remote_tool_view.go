package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef/mcp/catalogue"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
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
// loading. It warns when an override takes the name of an upstream tool that
// has no override (the override wins and the upstream tool is hidden, the
// same rule the tools/list rewrite applies), when an override's source tool
// is not in the catalogue, and when the catalogue cannot be listed.
//
// Fetch scope: the check calls Proxy.TargetURL with the proxy's upstream
// transport (proxy URL, TLS settings, upstream mTLS certificate), the API's
// static global request headers and its upstream basic auth or OAuth; see
// remoteMCPCatalogueClient and remoteMCPCatalogueHeader. It does not use load
// balancing or service discovery, credentials or header values that need a
// client request (the MCP OAuth broker, request signing, forwarded client
// credentials, $tyk_context and $tyk_meta values, endpoint-level header
// injection) or custom plugins, and it does not follow redirects. APIs that
// depend on those get the "could not list" warning.
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
	warnRemoteMCPRenamedAwaySettings(spec, view, logger)

	ctx, generation, done := spec.startRemoteMCPToolViewCheck(gw.ctx)
	targetURL := spec.Proxy.TargetURL

	go func() {
		defer close(done)

		checkCtx, cancelCheck := context.WithTimeout(ctx, remoteMCPCatalogueTimeout)
		defer cancelCheck()
		names, err := gw.fetchRemoteMCPToolNames(checkCtx, spec, targetURL, logger)
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
				Warning("MCP tool override takes the name of an upstream tool that has no override; the override wins and the upstream tool is hidden")
		}
		for _, source := range missing {
			logger.WithField("source_tool", source).Warning("MCP tool override source tool is not in the upstream tool list; it is not exposed")
		}
	}()
}

// warnRemoteMCPRenamedAwaySettings warns about every per-tool setting in the
// API definition whose meaning the overrides change: middleware.mcpTools
// entries, which carry the API's tool allow and block rules, rate limits and
// other tool middleware. Tool settings match exposed names, so an entry for
// an upstream tool that was renamed away no longer applies to any tool, and
// an entry for an upstream tool whose name another override took (a swap or
// a chained rename) now applies to that other upstream tool. This is the rule
// the Dashboard applies on save. Wildcard entries are left alone, since they
// may match other tools on purpose. Enforcement is not changed.
func warnRemoteMCPRenamedAwaySettings(spec *APISpec, view *tooloverride.View, logger *logrus.Entry) {
	middleware := oasMiddleware(spec)
	if middleware == nil {
		return
	}
	names := make([]string, 0, len(middleware.McpTools))
	for name := range middleware.McpTools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.Contains(name, "*") {
			continue
		}
		if exposed, renamedAway := view.RenamedAway(name); renamedAway {
			logger.WithFields(logrus.Fields{"setting": "middleware.mcpTools", "tool": name, "exposed_name": exposed}).
				Warning("MCP tool setting names a tool that an x-tyk-mcp-server override renamed; it no longer applies, configure it under the exposed name")
		}
		if source, taken := view.NameTakenBy(name); taken {
			logger.WithFields(logrus.Fields{"setting": "middleware.mcpTools", "tool": name, "upstream_tool": source}).
				Warning("MCP tool setting names a tool whose name an x-tyk-mcp-server override gave to another upstream tool; it now applies to upstream tool " + source)
		}
	}
}

// fetchRemoteMCPToolNames lists the upstream catalogue the way the proxy
// reaches the upstream; see remoteMCPCatalogueClient and
// remoteMCPCatalogueHeader.
func (gw *Gateway) fetchRemoteMCPToolNames(ctx context.Context, spec *APISpec, targetURL string, logger *logrus.Entry) ([]string, error) {
	client, release, err := gw.remoteMCPCatalogueClient(spec, logger)
	if err != nil {
		return nil, err
	}
	defer release()
	requestHeader, err := gw.remoteMCPCatalogueHeader(ctx, spec, logger)
	if err != nil {
		return nil, err
	}
	return catalogue.FetchToolNames(ctx, client, targetURL, requestHeader)
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
	now := time.Now()
	if err != nil {
		if spec.mcpResponseWarnings.due("rewrite", now) {
			logger.WithError(err).Warning("Upstream tools/list response was not rewritten with MCP tool overrides; it is passed through unchanged")
		}
		return body, false
	}
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
	for _, source := range drift.Malformed {
		if view.ShouldWarnMalformed(source, now) {
			logger.WithField("source_tool", source).Warning("Upstream MCP tool could not be merged with its tool override and is omitted from tools/list; the rest of the list is rewritten")
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
