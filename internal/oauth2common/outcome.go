package oauth2common

import (
	"errors"
	"time"
)

// OutcomeKind is the bounded classification of one exchange decision. It is
// safe as a metric label (a small fixed enum) and is the join key between the
// metric label, the structured log line, and the audit event.
type OutcomeKind string

const (
	// OutcomeOK: the exchange produced a token (whether freshly from the IdP
	// or served from cache — cache status is a separate signal, not an
	// outcome).
	OutcomeOK OutcomeKind = "ok"
	// OutcomeIdPError: the IdP rejected the exchange, or the call to it failed.
	OutcomeIdPError OutcomeKind = "idp_error"
	// OutcomeMisconfig: exchange is configured but the target is unresolvable
	// at request time (e.g. an unresolvable client secret).
	OutcomeMisconfig OutcomeKind = "misconfig"
	// OutcomeNoMatchingProvider: the inbound token's issuer matched no
	// configured provider.
	OutcomeNoMatchingProvider OutcomeKind = "no_matching_provider"
	// OutcomeStepUpRequired: a jwt-bearer exchange returned a claims challenge
	// (interaction_required). An expected control-flow event relayed to the
	// caller as a 401 insufficient_claims challenge — not an idp_error.
	OutcomeStepUpRequired OutcomeKind = "step_up_required"
)

// ClassifyExchangeOutcome maps an exchange result to its bounded OutcomeKind.
// A nil error is ok; the typed rejections map to their kind; any other error
// is treated as an IdP-side failure (it touched, or tried to touch, the IdP).
// The check sees through wrapping (errors.As).
func ClassifyExchangeOutcome(err error) OutcomeKind {
	if err == nil {
		return OutcomeOK
	}
	var noProvider *NoMatchingProviderError
	if errors.As(err, &noProvider) {
		return OutcomeNoMatchingProvider
	}
	var misconfig *MisconfigError
	if errors.As(err, &misconfig) {
		return OutcomeMisconfig
	}
	var stepUp *StepUpRequiredError
	if errors.As(err, &stepUp) {
		return OutcomeStepUpRequired
	}
	return OutcomeIdPError
}

// Outcome captures the result of one RFC 8693 exchange attempt for structured logging.
type Outcome struct {
	// ProviderName is the matched provider; empty when no exchange ran.
	ProviderName string

	// Audience is the resolved audience sent to the IdP.
	Audience string

	// Scopes is the resolved scope list sent to the IdP.
	Scopes []string

	// ExchangedToken is the IdP's exchanged access token; empty on failure.
	ExchangedToken string

	// CacheHit reports whether the token was served from cache (no IdP round-trip).
	CacheHit bool

	// Duration is the time spent obtaining the exchanged token — the IdP
	// round-trip on a miss, the cache lookup on a hit; zero when the exchange
	// failed before a fetch was attempted.
	Duration time.Duration

	// IdpErrorCode and IdpErrorDesc carry the IdP's error code and (capped)
	// description on an idp_error outcome. Never metric labels — logs/audit only.
	IdpErrorCode string
	IdpErrorDesc string
}
