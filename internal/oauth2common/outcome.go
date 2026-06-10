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
	// OutcomeActorNotAuthorized: the requireMayAct pre-flight rejected the
	// configured actor before any IdP call (gateway-side policy refusal).
	OutcomeActorNotAuthorized OutcomeKind = "actor_not_authorized"
	// OutcomeMissingActorToken: a required header-source actor token was absent
	// from the inbound request — a client-side failure that never reached the
	// IdP, so it must not be counted as an idp_error.
	OutcomeMissingActorToken OutcomeKind = "missing_actor_token"
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
	var actorNotAuthorized *ActorNotAuthorizedError
	if errors.As(err, &actorNotAuthorized) {
		return OutcomeActorNotAuthorized
	}
	var missingActor *MissingActorTokenError
	if errors.As(err, &missingActor) {
		return OutcomeMissingActorToken
	}
	return OutcomeIdPError
}

// Outcome captures the result of one RFC 8693 exchange attempt for structured logging.
type Outcome struct {
	// ProviderName is the matched provider; empty when no exchange ran.
	ProviderName string

	// ActorID identifies the delegating actor used to discriminate the cache
	// entry: the impersonation sentinel when no actor was attached, the actor
	// client id for client_credentials, or a HashActorID for header/static.
	ActorID string

	// ActorSource is the configured actor-token source (client_credentials /
	// header / static), empty for impersonation. ActorAzp is the actor client's
	// authorized party. Both feed the delegation observability fields (never
	// the actor's subject identity).
	ActorSource string
	ActorAzp    string

	// Audience is the resolved audience sent to the IdP.
	Audience string

	// Scopes is the resolved scope list sent to the IdP.
	Scopes []string

	// ExchangedToken is the IdP's exchanged access token; empty on failure.
	ExchangedToken string

	// CacheHit reports whether the token was served from cache (no IdP round-trip).
	CacheHit bool

	// Duration is the IdP round-trip latency; meaningful only when the outcome
	// reached the IdP (a cache hit leaves it zero).
	Duration time.Duration

	// IdpErrorCode and IdpErrorDesc carry the IdP's error code and (capped)
	// description on an idp_error outcome. Never metric labels — logs/audit only.
	IdpErrorCode string
	IdpErrorDesc string
}
