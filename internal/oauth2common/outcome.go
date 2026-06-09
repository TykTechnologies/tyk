package oauth2common

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
}
