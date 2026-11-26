package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
	mcpaggregator "github.com/TykTechnologies/tyk/internal/mcp/aggregator"
)

const (
	mcpAggregatorVersionUncheckedMsg = "MCP aggregator admits aggregated MCP proxy without a protocol version check"
	mcpAggregatorToolsUncheckedMsg   = "MCP aggregator admits aggregated MCP proxy without checking its tools"
)

const (
	// mcpAggregatorDefaultProbeTimeout bounds each step of the admission
	// probe of an aggregated MCP proxy, server/discover and the paged
	// tools/list, when the gateway sets no proxy_default_timeout.
	mcpAggregatorDefaultProbeTimeout = 10 * time.Second

	// The probe runs on behalf of no client, so aggregated proxies see a
	// loopback caller instead of the management API caller's address.
	mcpAggregatorProbeRemoteAddr = "127.0.0.1:0"
	mcpAggregatorProbeHost       = "localhost"
)

// mcpAggregatorProbeTimeout follows the gateway's upstream timeout, which bounds every
// upstream call the probe makes through an aggregated proxy. Each probe step
// gets the whole of it, so a slow server/discover never leaves the tools/list
// fallback without time to answer.
func (gw *Gateway) mcpAggregatorProbeTimeout() time.Duration {
	if seconds := gw.GetConfig().ProxyDefaultTimeout; seconds > 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	return mcpAggregatorDefaultProbeTimeout
}

// mcpAggregatorVersionMismatchError reports an aggregated MCP proxy that
// answered a 2026-07-28 request in a way that shows it does not serve it.
type mcpAggregatorVersionMismatchError struct {
	Method string
	Detail string
}

func (e *mcpAggregatorVersionMismatchError) Error() string {
	return fmt.Sprintf("version mismatch: %s on MCP %s: %s", e.Method, mcp.ModernProtocolVersion, e.Detail)
}

// mcpAggregatorVersionMismatch inspects one aggregated proxy response to a
// 2026-07-28 request and describes why it shows the proxy does not serve that
// version, or returns "". Structural signals apply to every method: a JSON-RPC
// -32022 error and a response that declares another protocol version. Text
// signals apply only to the discovery methods, so a tool result can never be
// mistaken for one: an error or HTTP 400 body saying "unsupported protocol
// version", as the MCP SDKs send, and an HTTP 400 or 404 asking for a session,
// which a sessionless 2026-07-28 request only gets from a legacy server.
func mcpAggregatorVersionMismatch(method string, status int, header http.Header, body []byte) string {
	if version := header.Get(mcp.HeaderProtocolVersion); version != "" && version != mcp.ModernProtocolVersion {
		return fmt.Sprintf("upstream answered on %s", version)
	}
	textSignals := method == mcp.MethodServerDiscover || method == mcp.MethodToolsList
	legacySession := textSignals && (status == http.StatusBadRequest || status == http.StatusNotFound)

	message := body
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(header.Get(headerContentType))), "text/event-stream") {
		if event, err := mcpAggregatorEventStreamResponse(body); err == nil {
			message = event
		}
	}
	var resp struct {
		Error *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
		Result struct {
			Meta map[string]json.RawMessage `json:"_meta"`
		} `json:"result"`
	}
	if err := json.Unmarshal(message, &resp); err != nil {
		text := string(body)
		switch {
		case textSignals && status == http.StatusBadRequest && mentionsUnsupportedProtocolVersion(text):
			return "upstream rejected it: " + mcpAggregatorShortText(text)
		case legacySession && asksForLegacySession(text):
			return "upstream requires a legacy session: " + mcpAggregatorShortText(text)
		}
		return ""
	}
	if resp.Error != nil {
		switch {
		case resp.Error.Code == mcp.CodeUnsupportedProtocolVersion || textSignals && mentionsUnsupportedProtocolVersion(resp.Error.Message):
			detail := "upstream rejected it: " + mcpAggregatorShortText(resp.Error.Message)
			var data struct {
				Supported []string `json:"supported"`
			}
			if json.Unmarshal(resp.Error.Data, &data) == nil && len(data.Supported) > 0 {
				detail += " (supported: " + strings.Join(data.Supported, ", ") + ")"
			}
			return detail
		case legacySession && asksForLegacySession(resp.Error.Message):
			return "upstream requires a legacy session: " + mcpAggregatorShortText(resp.Error.Message)
		}
		return ""
	}
	var declared string
	if json.Unmarshal(resp.Result.Meta[mcp.MetaKeyProtocolVersion], &declared) == nil && declared != "" && declared != mcp.ModernProtocolVersion {
		return fmt.Sprintf("upstream answered on %s", declared)
	}
	return ""
}

// asksForLegacySession matches the replies stateful MCP SDK servers give to a
// request without a session: "Mcp-Session-Id header is required", "No valid
// session ID provided", "Session not found", "Server not initialized",
// "Missing session ID", "Invalid session ID" and "... is invalid during
// session initialization". Only these SDK forms count, so an application
// error such as "invalid session token" or "Database not initialized" from a
// modern upstream is reported as that upstream failing, not as a version
// mismatch.
func asksForLegacySession(text string) bool {
	text = strings.ToLower(text)
	for _, phrase := range []string{
		"mcp-session-id",
		"no valid session id",
		"missing session id",
		"invalid session id",
		"session not found",
		"server not initialized",
		"invalid during session initialization",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

func mentionsUnsupportedProtocolVersion(text string) bool {
	return strings.Contains(strings.ToLower(text), "unsupported protocol version")
}

func mcpAggregatorShortText(text string) string {
	text = strings.TrimSpace(text)
	if line, _, found := strings.Cut(text, "\n"); found {
		text = line
	}
	const limit = 200
	if len(text) > limit {
		text = text[:limit] + "..."
	}
	return text
}

// mcpAggregatorProbe is what the admission probe learnt about one aggregated
// MCP proxy.
type mcpAggregatorProbe struct {
	// Version is nil when server/discover confirms 2026-07-28, a version
	// mismatch error when the proxy does not serve it, and any other error
	// when the check could not be made.
	Version error
	// Tools are the names of the tools in the proxy's own tool view that the
	// aggregator selects, every tool without a selection; nil when ToolsErr
	// says why the tools could not be listed.
	Tools    []string
	ToolsErr error
}

// probeUpstream reads an aggregated MCP proxy once for admission: it checks
// that the proxy serves 2026-07-28 and lists its complete current tool view,
// keeping the tools selection selects. It asks server/discover, then follows
// every tools/list page, which also serves as the version check for proxies
// whose upstream does not answer discovery. Once server/discover confirms
// 2026-07-28, a failing tools/list only means the tools could not be checked,
// whatever the error looks like.
//
// An upstream without server/discover whose tools/list answers a sessionless
// 2026-07-28 request is reported as unconfirmed rather than as a mismatch:
// header-unaware 2025-03-26 servers and modern servers that skip the optional
// discovery answer alike, and rejecting the latter would break them.
func (d mcpAggregatorDispatcher) probeUpstream(parent *http.Request, spec *APISpec, alias string, selection mcpAggregatorToolSelection) mcpAggregatorProbe {
	trust := &mcpAggregatorLoopTrust{
		OrgID:           d.aggregator.OrgID,
		AggregatorAPIID: d.aggregator.APIID,
		UpstreamAPIID:   spec.APIID,
		Probe:           true,
	}
	confirmed := false
	raw, err := d.probeStep(parent, spec, mcp.MethodServerDiscover, trust)
	if err == nil {
		var result struct {
			SupportedVersions []string `json:"supportedVersions"`
		}
		if json.Unmarshal(raw, &result) == nil && result.SupportedVersions != nil {
			if !slices.Contains(result.SupportedVersions, mcp.ModernProtocolVersion) {
				return mcpAggregatorProbe{Version: &mcpAggregatorVersionMismatchError{
					Method: mcp.MethodServerDiscover,
					Detail: "upstream supports only " + strings.Join(result.SupportedVersions, ", "),
				}}
			}
			confirmed = true
		} else {
			err = errors.New("server/discover result has no supportedVersions")
		}
	}
	if isMCPAggregatorVersionMismatch(err) {
		return mcpAggregatorProbe{Version: err}
	}

	exposed, listErr := d.probeTools(parent, spec, alias, trust, selection)
	switch {
	case listErr != nil && confirmed:
		return mcpAggregatorProbe{ToolsErr: fmt.Errorf("tools/list: %w", listErr)}
	case isMCPAggregatorVersionMismatch(listErr):
		return mcpAggregatorProbe{Version: listErr}
	case listErr != nil:
		return mcpAggregatorProbe{
			Version:  fmt.Errorf("server/discover: %w; tools/list: %w", err, listErr),
			ToolsErr: fmt.Errorf("tools/list: %w", listErr),
		}
	}
	probe := mcpAggregatorProbe{Tools: make([]string, 0, len(exposed))}
	for _, tool := range exposed {
		probe.Tools = append(probe.Tools, tool.Name)
	}
	if !confirmed {
		probe.Version = fmt.Errorf("%w: %w; tools/list answered without declaring a version", errMCPAggregatorVersionUnconfirmed, err)
	}
	return probe
}

// probeStep sends one probe request within its own probe timeout.
func (d mcpAggregatorDispatcher) probeStep(parent *http.Request, spec *APISpec, method string, trust *mcpAggregatorLoopTrust) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(parent.Context(), d.gw.mcpAggregatorProbeTimeout())
	defer cancel()
	return d.send(parent.WithContext(ctx), spec, method, map[string]any{}, trust)
}

// probeTools reads every tools/list page of an aggregated MCP proxy within
// its own probe timeout.
func (d mcpAggregatorDispatcher) probeTools(parent *http.Request, spec *APISpec, alias string, trust *mcpAggregatorLoopTrust, selection mcpAggregatorToolSelection) ([]mcpAggregatorExposedTool, error) {
	ctx, cancel := context.WithTimeout(parent.Context(), d.gw.mcpAggregatorProbeTimeout())
	defer cancel()
	return d.exposedTools(parent.WithContext(ctx), spec, alias, trust, selection)
}

var errMCPAggregatorVersionUnconfirmed = errors.New("2026-07-28 support not confirmed")

func isMCPAggregatorVersionMismatch(err error) bool {
	var mismatch *mcpAggregatorVersionMismatchError
	return errors.As(err, &mismatch)
}

// validateMCPAggregatorUpstreamViews probes the given aggregated MCP proxies
// of an incoming aggregator once, refs[i] served by upstreams[i], and rejects
// the aggregator when one of them does not serve 2026-07-28, or when its tool
// selection does not fit the proxy's current tool view (see mcpAggregatorSelectionError). A proxy that cannot be
// checked, for example because its upstream is down, is admitted with a
// warning: the runtime omits it from tools/list until it answers, as it does
// any failing aggregated proxy, and applies its selection from then on.
func (gw *Gateway) validateMCPAggregatorUpstreamViews(r *http.Request, aggregator *APISpec, refs []oas.TykMCPAggregatorUpstream, upstreams []*APISpec) (string, int) {
	ctx := context.Background()
	if r != nil {
		ctx = r.Context()
	}
	parent := (&http.Request{Header: http.Header{}, Host: mcpAggregatorProbeHost, RemoteAddr: mcpAggregatorProbeRemoteAddr}).WithContext(ctx)

	dispatcher := mcpAggregatorDispatcher{gw: gw, aggregator: aggregator}
	probes := make([]mcpAggregatorProbe, len(upstreams))
	var wg sync.WaitGroup
	for i, spec := range upstreams {
		wg.Add(1)
		go func(i int, spec *APISpec) {
			defer wg.Done()
			selection := newMCPAggregatorToolSelection(mcpaggregator.Upstream{APIID: refs[i].APIID, Alias: refs[i].Alias, Tools: refs[i].Tools})
			probes[i] = dispatcher.probeUpstream(parent, spec, refs[i].Alias, selection)
		}(i, spec)
	}
	wg.Wait()

	for i, probe := range probes {
		var mismatch *mcpAggregatorVersionMismatchError
		if errors.As(probe.Version, &mismatch) {
			return fmt.Sprintf("aggregated MCP proxy %q does not support MCP version %s: %s", refs[i].APIID, mcp.ModernProtocolVersion, mismatch.Detail), http.StatusBadRequest
		}
	}
	for i, probe := range probes {
		if probe.ToolsErr != nil {
			continue
		}
		if msg := mcpAggregatorSelectionError(refs[i], probe.Tools); msg != "" {
			return msg, http.StatusBadRequest
		}
	}
	for i, probe := range probes {
		fields := logrus.Fields{
			"aggregator_api_id": aggregator.APIID,
			"upstream_api_id":   refs[i].APIID,
			"alias":             refs[i].Alias,
		}
		if probe.Version != nil {
			log.WithFields(fields).WithField("reason", probe.Version.Error()).Warn(mcpAggregatorVersionUncheckedMsg)
		}
		if probe.ToolsErr != nil {
			log.WithFields(fields).WithField("reason", probe.ToolsErr.Error()).Warn(mcpAggregatorToolsUncheckedMsg)
		}
		// Without a selection, a tool whose aggregated name is too long is
		// omitted at runtime, as it is when the proxy gains one later.
		if refs[i].Tools == nil {
			for _, tool := range probe.Tools {
				if reason, tooLong := mcpAggregatorNameTooLong(refs[i].Alias, tool); tooLong {
					log.WithFields(fields).WithField("tool", tool).WithField("reason", reason).Warn(mcpAggregatorToolNameTooLongMsg)
				}
			}
		}
	}
	return "", 0
}

// mcpAggregatorSelectionError checks an aggregated MCP proxy's tool selection
// against the names in the proxy's own tool view. Every selected name must be
// one the proxy exposes, so a typo is never an empty selection and a selection
// can only narrow what the proxy exposes, never widen it. The aggregated name
// of every selected tool must fit MCP's tool name limit: a tool selected by
// name has to be served. Without a selection, a tool whose aggregated name is
// too long is omitted with a warning instead, at admission as at runtime.
func mcpAggregatorSelectionError(ref oas.TykMCPAggregatorUpstream, exposed []string) string {
	exposedSet := make(map[string]struct{}, len(exposed))
	for _, tool := range exposed {
		exposedSet[tool] = struct{}{}
	}
	for _, tool := range ref.Tools {
		if _, ok := exposedSet[tool]; !ok {
			return fmt.Sprintf("tool %q not found in aggregated MCP proxy %q", tool, ref.Alias)
		}
	}
	for _, tool := range ref.Tools {
		if reason, tooLong := mcpAggregatorNameTooLong(ref.Alias, tool); tooLong {
			return fmt.Sprintf("tool %q of aggregated MCP proxy %q cannot be aggregated: %s", tool, ref.Alias, reason)
		}
	}
	return ""
}
