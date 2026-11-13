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
)

const mcpAggregatorVersionUncheckedMsg = "MCP aggregator admits aggregated MCP proxy without a protocol version check"

const (
	// mcpAggregatorDefaultProbeTimeout bounds the protocol version check of
	// all aggregated MCP proxies of one aggregator create or update when the
	// gateway sets no proxy_default_timeout.
	mcpAggregatorDefaultProbeTimeout = 10 * time.Second

	// The probe runs on behalf of no client, so aggregated proxies see a
	// loopback caller instead of the management API caller's address.
	mcpAggregatorProbeRemoteAddr = "127.0.0.1:0"
	mcpAggregatorProbeHost       = "localhost"
)

// mcpAggregatorProbeTimeout follows the gateway's upstream timeout, which bounds every
// upstream call the probe makes through an aggregated proxy.
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
// "Missing session ID" and "... is invalid during session initialization".
// Only session-id forms count, so an application error such as "invalid
// session token" from a modern upstream is not mistaken for one.
func asksForLegacySession(text string) bool {
	text = strings.ToLower(text)
	for _, phrase := range []string{
		"mcp-session-id",
		"session id",
		"session not found",
		"no valid session",
		"missing session",
		"not initialized",
		"during session initialization",
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

// probeVersion checks that an aggregated MCP proxy serves 2026-07-28. It asks
// server/discover first and falls back to tools/list for proxies whose
// upstream does not answer discovery. It returns a version mismatch error
// when the proxy does not serve 2026-07-28, nil when server/discover confirms
// it, and any other error when the check could not be made.
//
// An upstream without server/discover whose tools/list answers a sessionless
// 2026-07-28 request is reported as unconfirmed rather than as a mismatch:
// header-unaware 2025-03-26 servers and modern servers that skip the optional
// discovery answer alike, and rejecting the latter would break them.
func (d mcpAggregatorDispatcher) probeVersion(parent *http.Request, spec *APISpec) error {
	trust := &mcpAggregatorLoopTrust{
		OrgID:           d.aggregator.OrgID,
		AggregatorAPIID: d.aggregator.APIID,
		UpstreamAPIID:   spec.APIID,
		Probe:           true,
	}
	raw, err := d.send(parent, spec, mcp.MethodServerDiscover, map[string]any{}, trust)
	if err == nil {
		var result struct {
			SupportedVersions []string `json:"supportedVersions"`
		}
		if json.Unmarshal(raw, &result) == nil && result.SupportedVersions != nil {
			if slices.Contains(result.SupportedVersions, mcp.ModernProtocolVersion) {
				return nil
			}
			return &mcpAggregatorVersionMismatchError{
				Method: mcp.MethodServerDiscover,
				Detail: "upstream supports only " + strings.Join(result.SupportedVersions, ", "),
			}
		}
		err = errors.New("server/discover result has no supportedVersions")
	}
	if isMCPAggregatorVersionMismatch(err) {
		return err
	}
	if _, listErr := d.send(parent, spec, mcp.MethodToolsList, map[string]any{}, trust); listErr != nil {
		if isMCPAggregatorVersionMismatch(listErr) {
			return listErr
		}
		return fmt.Errorf("server/discover: %v; tools/list: %w", err, listErr)
	}
	return fmt.Errorf("%w: %v; tools/list answered without declaring a version", errMCPAggregatorVersionUnconfirmed, err)
}

var errMCPAggregatorVersionUnconfirmed = errors.New("2026-07-28 support not confirmed")

func isMCPAggregatorVersionMismatch(err error) bool {
	var mismatch *mcpAggregatorVersionMismatchError
	return errors.As(err, &mismatch)
}

// validateMCPAggregatorUpstreamVersions probes every aggregated MCP proxy of
// an incoming aggregator on 2026-07-28 and rejects the aggregator when one of
// them does not serve it. A proxy that cannot be checked, for example because
// its upstream is down, is admitted with a warning: the runtime omits it from
// tools/list until it answers, as it does any failing aggregated proxy.
func (gw *Gateway) validateMCPAggregatorUpstreamVersions(r *http.Request, aggregator *APISpec, ext *oas.TykMCPAggregator, upstreams []*APISpec) (string, int) {
	ctx := context.Background()
	if r != nil {
		ctx = r.Context()
	}
	ctx, cancel := context.WithTimeout(ctx, gw.mcpAggregatorProbeTimeout())
	defer cancel()
	parent := (&http.Request{Header: http.Header{}, Host: mcpAggregatorProbeHost, RemoteAddr: mcpAggregatorProbeRemoteAddr}).WithContext(ctx)

	dispatcher := mcpAggregatorDispatcher{gw: gw, aggregator: aggregator}
	errs := make([]error, len(upstreams))
	var wg sync.WaitGroup
	for i, spec := range upstreams {
		wg.Add(1)
		go func(i int, spec *APISpec) {
			defer wg.Done()
			errs[i] = dispatcher.probeVersion(parent, spec)
		}(i, spec)
	}
	wg.Wait()

	for i, err := range errs {
		var mismatch *mcpAggregatorVersionMismatchError
		if errors.As(err, &mismatch) {
			return fmt.Sprintf("aggregated MCP proxy %q does not support MCP version %s: %s", ext.Upstreams[i].APIID, mcp.ModernProtocolVersion, mismatch.Detail), http.StatusBadRequest
		}
	}
	for i, err := range errs {
		if err != nil {
			log.WithFields(logrus.Fields{
				"aggregator_api_id": aggregator.APIID,
				"upstream_api_id":   ext.Upstreams[i].APIID,
				"alias":             ext.Upstreams[i].Alias,
				"reason":            err.Error(),
			}).Warn(mcpAggregatorVersionUncheckedMsg)
		}
	}
	return "", 0
}
