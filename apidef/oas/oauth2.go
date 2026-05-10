package oas

import (
	"github.com/getkin/kin-openapi/openapi3"
)

// OAuth2 is the container for the new-style OAuth 2.0 security scheme.
// It carries the master Enabled toggle and inherits the AuthSources
// contract used by every Tyk security scheme.
//
// Stored under
// x-tyk-api-gateway.server.authentication.securitySchemes[name].
type OAuth2 struct {
	// Enabled is the master switch for this scheme. When false, the
	// entire oauth2 block is inert.
	Enabled bool `bson:"enabled" json:"enabled"`

	// AuthSources configures where the bearer token is read from
	// (Authorization header by default; cookie / query alternatives).
	AuthSources `bson:",inline" json:",inline"`
}

// HasContent reports whether the OAuth2 block carries operator
// configuration. With only the master toggle defined here, the toggle
// state is the entire signal.
func (o *OAuth2) HasContent() bool {
	return o != nil && o.Enabled
}

// IsEmpty is the inverse of HasContent. Used at fill time to decide
// whether to materialise the OAS-side scheme.
func (o *OAuth2) IsEmpty() bool {
	return !o.HasContent()
}

// fillOAuth2 walks the configured Tyk security schemes and materialises
// any pre-typed *OAuth2 entries into the public OAS document.
func (s *OAS) fillOAuth2() {
	tykAuth := s.getTykAuthentication()
	if tykAuth == nil || tykAuth.SecuritySchemes == nil {
		return
	}

	for name, scheme := range tykAuth.SecuritySchemes {
		oauth2, ok := scheme.(*OAuth2)
		if !ok {
			continue
		}
		if oauth2.IsEmpty() {
			continue
		}

		// Normalise the cached representation back into the map so
		// future reads return the typed struct.
		tykAuth.SecuritySchemes[name] = oauth2

		// Configured-but-disabled: keep in the Tyk extension so the
		// operator's settings round-trip, but do not advertise the
		// scheme in the public OAS document.
		if !oauth2.Enabled {
			continue
		}

		s.fillOAuth2OASScheme(name, oauth2)
		s.appendSecurity(name)
	}
}

// fillOAuth2OASScheme materialises a minimal oauth2 OAS Components
// entry for the named scheme with an empty
// `flows.authorizationCode.scopes` map.
//
// The OAS spec requires at least one flow on an oauth2 scheme, and
// authorizationCode requires both authorizationUrl and tokenUrl. We
// emit relative paths as placeholders rather than dummy external
// `https://example.com/…` URLs so the saved document doesn't claim
// an unrelated host. Sub-blocks that bring real endpoints (token
// exchange, introspection) override these at materialise time.
func (s *OAS) fillOAuth2OASScheme(name string, _ *OAuth2) {
	if s.Components == nil {
		s.Components = &openapi3.Components{}
	}
	if s.Components.SecuritySchemes == nil {
		s.Components.SecuritySchemes = make(openapi3.SecuritySchemes)
	}
	s.Components.SecuritySchemes[name] = &openapi3.SecuritySchemeRef{
		Value: &openapi3.SecurityScheme{
			Type: typeOAuth2,
			Flows: &openapi3.OAuthFlows{
				AuthorizationCode: &openapi3.OAuthFlow{
					AuthorizationURL: "/oauth/authorize",
					TokenURL:         "/oauth/token",
					Scopes:           map[string]string{},
				},
			},
		},
	}
}

// GetTykOAuth2Config returns the typed *OAuth2 configuration for the
// named security scheme, or nil when the scheme is not configured under
// x-tyk-api-gateway as a new-style OAuth2 scheme.
func (s *OAS) GetTykOAuth2Config(name string) *OAuth2 {
	tykAuth := s.getTykAuthentication()
	if tykAuth == nil || tykAuth.SecuritySchemes == nil {
		return nil
	}
	scheme, ok := tykAuth.SecuritySchemes[name]
	if !ok {
		return nil
	}
	oauth2, ok := scheme.(*OAuth2)
	if !ok {
		return nil
	}
	return oauth2
}

// IsOAuth2Scheme reports whether the named security scheme is a Tyk
// new-style OAuth2 scheme.
func (s *OAS) IsOAuth2Scheme(name string) bool {
	return s.GetTykOAuth2Config(name) != nil
}

