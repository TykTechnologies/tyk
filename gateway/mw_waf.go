package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/wafjs"
)

// WAF provenance pin. It must match the loaded artifacts and
// docs/dev/program/waf-js/crs-pin-provenance.md; it changes only through a
// contract amendment.
const (
	wafCRSRelease        = "v4.25.1"
	wafCRSManifestSHA256 = "0539e66e7627fe71c160a644d8fb7ab6e450d53c9de208be5f95a35c70e1a154"
)

// wafClientError is rendered by the gateway error handler. It separates
// fixed client-facing policy messages from internal errors and their details.
type wafClientError string

func (e wafClientError) Error() string {
	return string(e)
}

// Client-facing WAF errors. They are fixed strings: rule IDs, scores, and
// transaction IDs never enter a client response.
const (
	wafBlockError       wafClientError = "Request blocked by security policy"
	wafUnavailableError wafClientError = "Request rejected by security policy"
)

// wafDefaultInspectionTimeout bounds one inspection when neither the global
// inspection limit nor a per-API timeout is set.
const wafDefaultInspectionTimeout = time.Second

// WAFMiddleware adapts the gateway request to the waf-js engine host and
// enforces its verdict. The adapter stays thin: snapshot curation,
// inspection, and engine lifecycle live in internal/wafjs; this middleware
// only resolves configuration, logs the decision, and enforces the outcome.
//
// Enablement follows the WAF global flag, the per-API WAF flag, and the
// MCP/JSON-RPC exclusion. It never consults EnableJSVM and is independent
// of CustomMiddleware.Driver: WAF enablement changes neither plugin
// availability nor dispatch.
type WAFMiddleware struct {
	*BaseMiddleware

	host         *wafjs.Host
	blockMode    bool
	failClosed   bool
	inspectionTO time.Duration
}

var _ TykMiddleware = (*WAFMiddleware)(nil)

// Name implements TykMiddleware.
func (m *WAFMiddleware) Name() string {
	return "WAFMiddleware"
}

// Init resolves the effective WAF configuration and builds the engine host
// once per API load. A build failure leaves the host inactive; every
// inspection then fails and the per-API failure policy applies until a
// reload builds a working engine.
func (m *WAFMiddleware) Init() {
	gwConf := m.Gw.GetConfig()
	m.blockMode = m.Spec.WAF.EffectiveMode() == apidef.WAFModeBlock
	m.failClosed = m.Spec.WAF.FailClosed
	m.inspectionTO = wafEffectiveInspectionTimeout(gwConf.WAF.InspectionLimit, m.Spec.WAF.TimeoutMs)

	m.Logger().WithFields(logrus.Fields{
		"mode":             m.Spec.WAF.EffectiveMode(),
		"fail_closed":      m.failClosed,
		"inspection_to_ms": m.inspectionTO.Milliseconds(),
		"body_limit":       wafEffectiveBodyLimit(gwConf.WAF.BodyLimit, m.Spec.WAF.BodyLimit),
		"pool_size":        gwConf.WAF.PoolSize,
	}).Debug("WAF middleware resolved configuration")

	m.host = wafjs.NewHost()
	cfg, err := wafHostConfig(gwConf.WAF.EnginePath, gwConf.WAF.RulesetPath)
	if err != nil {
		m.Logger().WithError(err).Error("WAF engine artifacts unavailable; inspections fail until reload")
		return
	}
	if err := m.host.Build(context.Background(), cfg); err != nil {
		m.Logger().WithError(err).Error("WAF engine build failed; inspections fail until reload")
	}
}

// EnabledForSpec implements TykMiddleware. The WAF runs only when the global
// flag and the per-API flag are both set, and never for MCP or JSON-RPC
// APIs; the exclusion is recorded as an unsupported feature, never silently
// omitted.
func (m *WAFMiddleware) EnabledForSpec() bool {
	if !m.Gw.GetConfig().WAF.Enabled {
		return false
	}
	if !m.Spec.WAF.Enabled {
		return false
	}
	if m.Spec.IsMCP() || m.Spec.JsonRpcVersion == apidef.JsonRPC20 {
		m.Logger().Info("WAF inspection does not support MCP or JSON-RPC APIs; recorded as an unsupported feature and skipped")
		return false
	}
	return true
}

// Config implements TykMiddleware. The WAF resolves its configuration from
// the global and per-API settings in Init, so there is no separate
// middleware configuration payload.
func (m *WAFMiddleware) Config() (interface{}, error) {
	return nil, nil
}

// ProcessRequest implements TykMiddleware. It inspects the curated snapshot
// and enforces the verdict: a block in block mode returns 403 with a fixed
// message and never reaches upstream; audit mode always continues upstream;
// inspection errors apply the per-API failure policy (fail-open continues
// upstream, fail-closed returns 503 with a fixed message).
//
//nolint:staticcheck // TykMiddleware fixes the (error, status) return order.
func (m *WAFMiddleware) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	ctx, cancel := context.WithTimeout(r.Context(), m.inspectionTO)
	defer cancel()

	finding, err := m.host.Inspect(ctx, wafSnapshotOf(r))
	if err != nil {
		m.Logger().WithError(err).WithField("fail_closed", m.failClosed).Error("WAF inspection failed")
		if !m.failClosed {
			return nil, http.StatusOK
		}
		return wafUnavailableError, http.StatusServiceUnavailable
	}

	if finding.Verdict != wafjs.VerdictBlock {
		return nil, http.StatusOK
	}

	m.Logger().WithFields(logrus.Fields{
		"mode":             m.Spec.WAF.EffectiveMode(),
		"verdict":          string(finding.Verdict),
		"enforced":         m.blockMode,
		"anomaly_score":    finding.AnomalyScore,
		"matched_rule_ids": finding.MatchedRuleIDs,
		"inspection_scope": finding.InspectionScope,
		"body_inspected":   finding.BodyInspected,
		"skip_reason":      finding.SkipReason,
	}).Info("WAF inspection decision")

	if !m.blockMode {
		// Audit mode always continues upstream.
		return nil, http.StatusOK
	}

	// Block mode: fixed message, no rule details, upstream never reached.
	return wafBlockError, http.StatusForbidden
}

// Unload implements TykMiddleware. It closes this API's engine host only
// after its replacement is ready: reloads build the new spec's host during
// its own Init before the old spec's unload hooks run, and wafjs swaps
// engines atomically inside a host.
func (m *WAFMiddleware) Unload() {
	if m.host != nil {
		if err := m.host.Close(); err != nil {
			m.Logger().WithError(err).Warn("WAF engine close failed")
		}
	}
}

// wafEffectiveInspectionTimeout resolves the inspection bound: a per-API
// timeout overrides the global inspection limit, which overrides the
// gateway default.
func wafEffectiveInspectionTimeout(globalLimitMs, apiTimeoutMs int) time.Duration {
	switch {
	case apiTimeoutMs > 0:
		return time.Duration(apiTimeoutMs) * time.Millisecond
	case globalLimitMs > 0:
		return time.Duration(globalLimitMs) * time.Millisecond
	default:
		return wafDefaultInspectionTimeout
	}
}

// wafEffectiveBodyLimit resolves the body-inspection bound: a per-API limit
// overrides the global default. Enforcement lands with the body-ABI bead;
// until then requests pass through untouched and the limit is recorded only.
func wafEffectiveBodyLimit(globalLimit, apiLimit int) int {
	if apiLimit > 0 {
		return apiLimit
	}
	if globalLimit > 0 {
		return globalLimit
	}
	return config.DefaultWAFBodyLimit
}

// wafHostConfig derives the wafjs host configuration from the configured
// artifact paths. Both paths resolve against the gateway working directory;
// the artifact root is the engine artifact's directory and the ruleset must
// stay inside the same root.
func wafHostConfig(enginePath, rulesetPath string) (wafjs.Config, error) {
	if enginePath == "" || rulesetPath == "" {
		return wafjs.Config{}, errors.New("waf: engine_path and ruleset_path must both be set")
	}
	absEngine, err := filepath.Abs(enginePath)
	if err != nil {
		return wafjs.Config{}, fmt.Errorf("waf: resolve engine path: %w", err)
	}
	absRuleset, err := filepath.Abs(rulesetPath)
	if err != nil {
		return wafjs.Config{}, fmt.Errorf("waf: resolve ruleset path: %w", err)
	}

	root := filepath.Dir(absEngine)
	rulesetRel, err := filepath.Rel(root, absRuleset)
	if err != nil || rulesetRel == ".." || filepath.IsAbs(rulesetRel) ||
		strings.HasPrefix(rulesetRel, ".."+string(filepath.Separator)) {
		return wafjs.Config{}, errors.New("waf: ruleset_path must stay inside the engine artifact directory")
	}

	return wafjs.Config{
		Root:        root,
		EnginePath:  filepath.Base(absEngine),
		RulesetPath: rulesetRel,
		CRSPin: wafjs.CRSPin{
			Release:        wafCRSRelease,
			ManifestSHA256: wafCRSManifestSHA256,
		},
	}, nil
}

// wafSnapshotOf builds the curated, read-only inspection snapshot. It never
// exposes *http.Request and never consumes the request body: body inspection
// and restoration land with the body-ABI bead, so bodies pass through
// byte-for-byte.
func wafSnapshotOf(r *http.Request) wafjs.RequestSnapshot {
	scheme := "http"
	if r.TLS != nil || r.URL.Scheme == "https" {
		scheme = "https"
	}
	requestURI := r.URL.RequestURI()
	if r.RequestURI != "" {
		requestURI = r.RequestURI
	}
	return wafjs.RequestSnapshot{
		Method:     r.Method,
		Scheme:     scheme,
		Host:       r.Host,
		RequestURI: requestURI,
		Path:       r.URL.Path,
		Proto:      r.Proto,
		Headers:    r.Header,
		Query:      r.URL.Query(),
		Cookies:    r.Cookies(),
	}
}
