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

	// Delegation (actor-token) fields. Carry only the actor's source and
	// client/party azp — never the actor subject identity (act.sub) or token.
	fieldActorSource        = "oauth2_actor_source"
	fieldActorAzp           = "oauth2_actor_azp"
	fieldDelegationObserved = "oauth2_delegation_observed"

	truncatedSuffix = "...(truncated)"
)

// EventPayload holds the bounded, non-PII signals describing one exchange
// decision. Following the no-hashing identity model, it carries only the
// client/party identifiers (which name an application, not a person) and never
// the subject identity or token id (jti / sub / act.sub / the raw act map) —
// those are dropped, not hashed. It holds no raw token material.
type EventPayload struct {
	TraceID  string
	APIID    string
	Provider string
	Outcome  oauth2common.OutcomeKind
	CacheHit bool
	// DurationMS is the IdP round-trip latency in milliseconds; meaningful
	// only when the outcome reached the IdP.
	DurationMS int64

	// IdpError / IdpErrorDesc are populated on an idp_error outcome. The
	// description is length-capped before emission.
	IdpError     string
	IdpErrorDesc string

	// SubjectAzp is the inbound token's authorized party (the calling app).
	SubjectAzp string
	// ExchangedAzp is the exchanged token's authorized party, when present.
	ExchangedAzp string
	// Audience and ScopesRequested are the resolved exchange target.
	Audience        string
	ScopesRequested []string

	// ActorSource is the configured actor-token source (client_credentials /
	// header / static); empty for impersonation. ActorAzp is the actor client's
	// authorized party. DelegationObserved is true when the exchanged token
	// carried an RFC 8693 `act` claim (the IdP honoured delegation).
	ActorSource        string
	ActorAzp           string
	DelegationObserved bool
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
		m[fieldSubjectAzp] = p.SubjectAzp
	}
	if p.ExchangedAzp != "" {
		m[fieldExchangedAzp] = p.ExchangedAzp
	}
	if p.Audience != "" {
		m[fieldAudience] = p.Audience
	}
	if len(p.ScopesRequested) > 0 {
		m[fieldScopesRequested] = p.ScopesRequested
	}
	if p.ActorSource != "" {
		m[fieldActorSource] = p.ActorSource
		m[fieldDelegationObserved] = p.DelegationObserved
		if p.ActorAzp != "" {
			m[fieldActorAzp] = p.ActorAzp
		}
	}
	if p.Outcome == oauth2common.OutcomeIdPError {
		if p.IdpError != "" {
			m[fieldIdpError] = capIdPErrorField(p.IdpError)
		}
		if p.IdpErrorDesc != "" {
			m[fieldIdpErrorDesc] = capIdPErrorField(p.IdpErrorDesc)
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

// capIdPErrorField bounds an IdP-supplied error code or description so an
// oversized (or hostile) IdP body cannot bloat a log line or audit event.
func capIdPErrorField(s string) string {
	if len(s) <= oauth2common.MaxIdPErrorBodyBytes {
		return s
	}
	return s[:oauth2common.MaxIdPErrorBodyBytes] + truncatedSuffix
}
