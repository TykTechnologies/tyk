//go:build ee || dev

package oauth2tokenexchange

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
	tykotel "github.com/TykTechnologies/tyk/internal/otel"
)

// tracerName identifies this package's tracer in the OTel registry.
const tracerName = "github.com/TykTechnologies/tyk/ee/middleware/oauth2tokenexchange"

// exchangeSpanName is the dedicated span opened around the exchange step. It
// joins the request's existing trace — it does not start a new one.
const exchangeSpanName = "oauth2.exchange"

// Span attribute keys and cache-status values. Attributes carry only bounded
// provider / outcome / cache-status values — never a token or an identity
// (client identifiers live on logs + audit, not on the span).
const (
	spanAttrProvider    = "oauth2.exchange.provider"
	spanAttrOutcome     = "oauth2.exchange.outcome"
	spanAttrCacheStatus = "oauth2.exchange.cache_status"

	cacheStatusHit  = "hit"
	cacheStatusMiss = "miss"
)

// runExchangeObserved opens the oauth2.exchange span around the exchange step,
// runs it with the span's context (so the IdP round-trip nests as a child
// client span on a cache miss), stamps the bounded span attributes, and emits
// the metric / structured log / audit event. The span joins the request's
// existing trace rather than starting a new one.
func (m *Middleware) runExchangeObserved(r *http.Request, st *oauth2common.State) (oauth2common.Outcome, error) {
	ctx, span := otel.Tracer(tracerName).Start(r.Context(), exchangeSpanName)
	defer span.End()

	out, err := m.runExchange(r.WithContext(ctx), st)
	outcome := oauth2common.ClassifyExchangeOutcome(err)

	span.SetAttributes(
		attribute.String(spanAttrProvider, out.ProviderName),
		attribute.String(spanAttrOutcome, string(outcome)),
		attribute.String(spanAttrCacheStatus, cacheStatus(out.CacheHit)),
	)

	m.emitObservability(ctx, st, out, outcome)
	return out, err
}

// emitObservability records the exchange metric, writes the structured log
// line, and fires the audit event (when the outcome is audited).
func (m *Middleware) emitObservability(ctx context.Context, st *oauth2common.State, out oauth2common.Outcome, outcome oauth2common.OutcomeKind) {
	m.Base.RecordExchangeMetric(ctx, string(outcome), out.ProviderName, out.Duration)
	if out.CacheHit {
		m.Base.RecordExchangeCacheHit(ctx, out.ProviderName)
	}

	payload := EventPayload{
		TraceID:         tykotel.ExtractTraceID(ctx),
		APIID:           st.APIID,
		Provider:        out.ProviderName,
		Outcome:         outcome,
		CacheHit:        out.CacheHit,
		DurationMS:      out.Duration.Milliseconds(),
		IdpError:        out.IdpErrorCode,
		IdpErrorDesc:    out.IdpErrorDesc,
		SubjectAzp:      oauth2common.StringClaim(st.Claims, oas.OAuth2ClaimAzp),
		ExchangedAzp:    exchangedAzp(out.ExchangedToken),
		Audience:        out.Audience,
		ScopesRequested: out.Scopes,
	}

	m.Logger().WithFields(payload.LogFields()).Info("oauth2 token exchange")

	if ev, audited := payload.AuditDecision(); audited {
		m.Base.FireEvent(apidef.TykEvent(ev), payload.AuditMeta())
	}
}

// cacheStatus maps the cache-hit flag to the span's cache_status value.
func cacheStatus(hit bool) string {
	if hit {
		return cacheStatusHit
	}
	return cacheStatusMiss
}

// exchangedAzp best-effort reads the authorized party of the exchanged token,
// for the non-PII oauth2_exchanged_azp field. Returns "" when absent or
// unparseable — the field then stays absent rather than empty.
func exchangedAzp(token string) string {
	if token == "" {
		return ""
	}
	claims, err := oauth2common.ParseUnverifiedClaims(token)
	if err != nil {
		return ""
	}
	return oauth2common.StringClaim(claims, oas.OAuth2ClaimAzp)
}
