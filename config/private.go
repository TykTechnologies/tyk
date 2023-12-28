package config

// Private contains configurations which are private, adding it to be part of config without exposing to customers.
type Private struct {
	OAuthTokensPurgeInterval int
}
