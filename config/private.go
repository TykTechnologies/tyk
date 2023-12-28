package config

import "time"

// Private contains configurations which are private, adding it to be part of config without exposing to customers.
type Private struct {
	OAuthTokensPurgeInterval int `json:"-"`
}

func (p Private) GetOAuthTokensPurgeInterval() time.Duration {
	var purgeInterval time.Duration
	if p.OAuthTokensPurgeInterval == 0 {
		purgeInterval = time.Hour
	} else {
		purgeInterval = time.Second * time.Duration(p.OAuthTokensPurgeInterval)
	}

	return purgeInterval
}
