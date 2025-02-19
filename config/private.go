package config

import "time"

// Private contains configurations which are private, adding it to be part of config without exposing to customers.
type Private struct {
	// OAuthTokensPurgeInterval specifies the interval at which lapsed tokens get purged.
	OAuthTokensPurgeInterval int `json:"-"`
	// OriginalPath is the path to the config file that is read. If
	// none was found, it's the path to the default config file that
	// was written.
	OriginalPath string `json:"-"`
	// OriginalAPIKeyPath is the original path to the API key in the configuration file. Only used to modify the external KV store in case of API Key Reset.
	// This is set automatically in afterConfSetup()
	OriginalAPIKeyPath string `json:"-"`
}

// GetOAuthTokensPurgeInterval returns purge interval for lapsed OAuth tokens.
func (p Private) GetOAuthTokensPurgeInterval() time.Duration {
	if p.OAuthTokensPurgeInterval != 0 {
		return time.Second * time.Duration(p.OAuthTokensPurgeInterval)
	}

	return time.Hour
}
