package oas

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

const certRefsTestCertID = "org1cert"

func newOASForCertRefs(mutate func(x *XTykAPIGateway)) *OAS {
	x := &XTykAPIGateway{}
	x.Info.State.Active = true
	mutate(x)

	s := &OAS{}
	s.SetTykExtension(x)
	return s
}

func tokenExchangeAuth(authEnabled, schemeEnabled, teEnabled bool, providers ...OAuth2TokenExchangeProvider) *Authentication {
	return &Authentication{
		Enabled: authEnabled,
		SecuritySchemes: SecuritySchemes{
			"oauth": &OAuth2{
				Enabled:       schemeEnabled,
				TokenExchange: &OAuth2TokenExchange{Enabled: teEnabled, Providers: providers},
			},
		},
	}
}

func tokenExchangeProvider(method, certID string) OAuth2TokenExchangeProvider {
	return OAuth2TokenExchangeProvider{Name: method, ClientAuth: &OAuth2ClientAuth{Method: method, CertID: certID}}
}

func certRefsTestUses(s *OAS) []apidef.CertificateUse {
	return s.CertificateReferences(nil).Uses(certRefsTestCertID, s.IsActive())
}

func TestOAS_CertificateReferences(t *testing.T) {
	use := func(t apidef.CertificateUseType, active bool) apidef.CertificateUse {
		return apidef.CertificateUse{Type: t, Active: active}
	}
	pkJWT := OAuth2ClientAuthPrivateKeyJWT

	tests := []struct {
		name   string
		mutate func(x *XTykAPIGateway)
		want   []apidef.CertificateUse
	}{
		{
			name:   "no reference",
			mutate: func(_ *XTykAPIGateway) {},
			want:   nil,
		},
		{
			name: "every use switched on",
			mutate: func(x *XTykAPIGateway) {
				x.Upstream.CertificatePinning = &CertificatePinning{
					Enabled:                   true,
					DomainToPublicKeysMapping: PinnedPublicKeys{{Domain: "*", PublicKeys: []string{certRefsTestCertID}}},
				}
				x.Upstream.MutualTLS = &MutualTLS{
					Enabled:              true,
					DomainToCertificates: []DomainToCertificate{{Domain: "*", Certificate: certRefsTestCertID}},
				}
				x.Server.ClientCertificates = &ClientCertificates{Enabled: true, Allowlist: []string{certRefsTestCertID}}
				x.Server.CustomDomain = &Domain{Enabled: true, Name: "example.com", Certificates: []string{certRefsTestCertID}}
				x.Upstream.Authentication = &UpstreamAuth{
					Enabled:        true,
					RequestSigning: &UpstreamRequestSigning{Enabled: true, Algorithm: "rsa-sha256", KeyID: "key", CertificateID: certRefsTestCertID},
				}
				x.Server.Authentication = tokenExchangeAuth(true, true, true, tokenExchangeProvider(pkJWT, certRefsTestCertID))
			},
			want: []apidef.CertificateUse{
				use(apidef.CertificateUsePinned, true),
				use(apidef.CertificateUseUpstream, true),
				use(apidef.CertificateUseClient, true),
				use(apidef.CertificateUseServer, true),
				use(apidef.CertificateUseRequestSigning, true),
				use(apidef.CertificateUseTokenExchange, true),
			},
		},
		{
			name: "every use switched off",
			mutate: func(x *XTykAPIGateway) {
				x.Upstream.CertificatePinning = &CertificatePinning{
					DomainToPublicKeysMapping: PinnedPublicKeys{{Domain: "*", PublicKeys: []string{certRefsTestCertID}}},
				}
				x.Upstream.MutualTLS = &MutualTLS{
					DomainToCertificates: []DomainToCertificate{{Domain: "*", Certificate: certRefsTestCertID}},
				}
				x.Server.ClientCertificates = &ClientCertificates{Allowlist: []string{certRefsTestCertID}}
				x.Server.CustomDomain = &Domain{Name: "example.com", Certificates: []string{certRefsTestCertID}}
				x.Upstream.Authentication = &UpstreamAuth{
					RequestSigning: &UpstreamRequestSigning{Algorithm: "rsa-sha256", CertificateID: certRefsTestCertID},
				}
				x.Server.Authentication = tokenExchangeAuth(true, true, false, tokenExchangeProvider(pkJWT, certRefsTestCertID))
			},
			want: []apidef.CertificateUse{
				use(apidef.CertificateUsePinned, false),
				use(apidef.CertificateUseUpstream, false),
				use(apidef.CertificateUseClient, false),
				use(apidef.CertificateUseServer, false),
				use(apidef.CertificateUseRequestSigning, false),
				use(apidef.CertificateUseTokenExchange, false),
			},
		},
		{
			name: "deactivated API",
			mutate: func(x *XTykAPIGateway) {
				x.Info.State.Active = false
				x.Server.ClientCertificates = &ClientCertificates{Enabled: true, Allowlist: []string{certRefsTestCertID}}
				x.Server.Authentication = tokenExchangeAuth(true, true, true, tokenExchangeProvider(pkJWT, certRefsTestCertID))
			},
			want: []apidef.CertificateUse{use(apidef.CertificateUseClient, false), use(apidef.CertificateUseTokenExchange, false)},
		},
		{
			name: "request signing with an hmac algorithm",
			mutate: func(x *XTykAPIGateway) {
				x.Upstream.Authentication = &UpstreamAuth{
					RequestSigning: &UpstreamRequestSigning{Enabled: true, Algorithm: "hmac-sha256", KeyID: "key", CertificateID: certRefsTestCertID},
				}
			},
			want: []apidef.CertificateUse{use(apidef.CertificateUseRequestSigning, false)},
		},
		{
			name: "token exchange with client_secret_basic",
			mutate: func(x *XTykAPIGateway) {
				x.Server.Authentication = tokenExchangeAuth(true, true, true, tokenExchangeProvider(OAuth2ClientAuthBasic, certRefsTestCertID))
			},
			want: []apidef.CertificateUse{use(apidef.CertificateUseTokenExchange, false)},
		},
		{
			name: "token exchange with server authentication switched off",
			mutate: func(x *XTykAPIGateway) {
				x.Server.Authentication = tokenExchangeAuth(false, true, true, tokenExchangeProvider(pkJWT, certRefsTestCertID))
			},
			want: []apidef.CertificateUse{use(apidef.CertificateUseTokenExchange, false)},
		},
		{
			name: "token exchange with the security scheme switched off",
			mutate: func(x *XTykAPIGateway) {
				x.Server.Authentication = tokenExchangeAuth(true, false, true, tokenExchangeProvider(pkJWT, certRefsTestCertID))
			},
			want: []apidef.CertificateUse{use(apidef.CertificateUseTokenExchange, false)},
		},
		{
			name: "token exchange with two providers referencing the certificate",
			mutate: func(x *XTykAPIGateway) {
				x.Server.Authentication = tokenExchangeAuth(true, true, true,
					tokenExchangeProvider(OAuth2ClientAuthBasic, certRefsTestCertID),
					tokenExchangeProvider(pkJWT, certRefsTestCertID),
				)
			},
			want: []apidef.CertificateUse{use(apidef.CertificateUseTokenExchange, true)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, certRefsTestUses(newOASForCertRefs(tc.mutate)))
		})
	}

	t.Run("token exchange read from an untyped security scheme, without storing it back", func(t *testing.T) {
		s := newOASForCertRefs(func(x *XTykAPIGateway) {
			x.Server.Authentication = tokenExchangeAuth(true, true, true, tokenExchangeProvider(pkJWT, certRefsTestCertID))
		})

		// A stored API definition holds security schemes as untyped maps.
		raw, err := json.Marshal(s)
		require.NoError(t, err)
		stored := &OAS{}
		require.NoError(t, json.Unmarshal(raw, stored))

		assert.Equal(t, []apidef.CertificateUse{use(apidef.CertificateUseTokenExchange, true)}, certRefsTestUses(stored))

		_, typed := stored.GetTykExtension().Server.Authentication.SecuritySchemes["oauth"].(*OAuth2)
		assert.False(t, typed)
	})

	t.Run("request signing honours hmacAllowedAlgorithms", func(t *testing.T) {
		s := newOASForCertRefs(func(x *XTykAPIGateway) {
			x.Upstream.Authentication = &UpstreamAuth{
				RequestSigning: &UpstreamRequestSigning{Enabled: true, Algorithm: "rsa-sha256", KeyID: "key", CertificateID: certRefsTestCertID},
			}
		})

		assert.Equal(t, []apidef.CertificateUse{use(apidef.CertificateUseRequestSigning, false)},
			s.CertificateReferences([]string{"hmac-sha256"}).Uses(certRefsTestCertID, true))
	})
}
