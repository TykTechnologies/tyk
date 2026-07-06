//go:build ee || dev

package oauth2tokenexchange

import (
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

// Observability field keys. These name the application, audience, scopes, and
// outcome — never a person or a token. They are a cross-cut contract shared by
// the structured log line and the audit-event meta, so they must not drift.
const (
	fieldTraceID         = "trace_id"
	fieldAPIID           = "oauth2_api_id"
	fieldProvider        = "oauth2_provider"
	fieldOutcome         = "oauth2_exchange_outcome"
	fieldCacheHit        = "oauth2_exchange_cache_hit"
	fieldDurationMS      = "duration_ms"
	fieldIdpError        = "oauth2_idp_error"
	fieldIdpErrorDesc    = "oauth2_idp_error_description"
	fieldSubjectAzp      = "oauth2_subject_azp"
	fieldExchangedAzp    = "oauth2_exchanged_azp"
	fieldAudience        = "oauth2_audience"
	fieldScopesRequested = "oauth2_scopes_requested"

	truncatedSuffix = "...(truncated)"
)

// EventPayload holds the bounded, non-PII signals describing one exchange
// decision. Following the no-hashing identity model, it carries only the
// client/party identifiers (which name an application, not a person) and never
// the subject identity or token id (jti / sub) — those are dropped, not
// hashed. It holds no raw token material.
type EventPayload struct {
	TraceID  string
	APIID    string
	Provider string
	Outcome  oauth2common.OutcomeKind
	CacheHit bool
	// DurationMS is the time spent obtaining the exchanged token in
	// milliseconds — the IdP round-trip on a miss, the cache lookup on a hit.
	DurationMS int64

	// IdpError / IdpErrorDesc are populated on an idp_error outcome. Both are
	// length-capped before emission.
	IdpError     string
	IdpErrorDesc string

	// SubjectAzp is the inbound token's authorized party (the calling app).
	SubjectAzp string
	// ExchangedAzp is the exchanged token's authorized party, when present.
	ExchangedAzp string
	// Audience and ScopesRequested are the resolved exchange target.
	Audience        string
	ScopesRequested []string
}

// LogFields returns the structured log line for one exchange: the same bounded
// safe fields as the audit meta, plus the IdP round-trip duration. No subject
// identity / token id / raw token is ever included.
func (p EventPayload) LogFields() logrus.Fields {
	f := logrus.Fields(p.AuditMeta())
	f[fieldDurationMS] = p.DurationMS
	return f
}

// AuditMeta returns the audit-event meta for one exchange — the same bounded
// oauth2_-namespaced safe fields as the log line.
func (p EventPayload) AuditMeta() map[string]interface{} {
	m := map[string]interface{}{
		fieldAPIID:    p.APIID,
		fieldProvider: p.Provider,
		fieldOutcome:  string(p.Outcome),
		fieldCacheHit: p.CacheHit,
	}
	p.addOptional(m)
	return m
}

// addOptional adds the present-only fields shared by LogFields and AuditMeta.
func (p EventPayload) addOptional(m map[string]interface{}) {
	if p.TraceID != "" {
		m[fieldTraceID] = p.TraceID
	}
	if p.SubjectAzp != "" {
		m[fieldSubjectAzp] = capField(p.SubjectAzp)
	}
	if p.ExchangedAzp != "" {
		m[fieldExchangedAzp] = capField(p.ExchangedAzp)
	}
	if p.Audience != "" {
		m[fieldAudience] = p.Audience
	}
	if len(p.ScopesRequested) > 0 {
		m[fieldScopesRequested] = p.ScopesRequested
	}
	if p.Outcome == oauth2common.OutcomeIdPError {
		if p.IdpError != "" {
			m[fieldIdpError] = capField(p.IdpError)
		}
		if p.IdpErrorDesc != "" {
			m[fieldIdpErrorDesc] = capField(p.IdpErrorDesc)
		}
	}
}

// AuditDecision returns the audit event type for this outcome and whether an
// audit event is emitted at all. ok audits as OAuth2ExchangeSucceeded;
// idp_error and no_matching_provider audit as OAuth2ExchangeFailed (the outcome
// distinguishes them); misconfig is an operator fault, not an authorization
// decision, so it is not audited (it still emits a metric and a log line).
func (p EventPayload) AuditDecision() (event.Event, bool) {
	switch p.Outcome {
	case oauth2common.OutcomeOK:
		return event.OAuth2ExchangeSucceeded, true
	case oauth2common.OutcomeIdPError, oauth2common.OutcomeNoMatchingProvider:
		return event.OAuth2ExchangeFailed, true
	default:
		return "", false
	}
}

// capField bounds an externally supplied value — an IdP error code or
// description, or a token claim — so an oversized (or hostile) peer cannot
// bloat a log line or audit event.
func capField(s string) string {
	if len(s) <= oauth2common.MaxIdPErrorBodyBytes {
		return s
	}
	return s[:oauth2common.MaxIdPErrorBodyBytes] + truncatedSuffix
}
