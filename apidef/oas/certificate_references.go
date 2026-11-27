package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
)

// IsActive reports whether the API is active, as set in info.state.active.
func (s *OAS) IsActive() bool {
	if ext := s.GetTykExtension(); ext != nil {
		return ext.Info.State.Active
	}
	return false
}

// CertificateReferences lists every place the Tyk OAS API definition names a certificate.
// hmacAllowedAlgorithms is the API's apidef.APIDefinition.HmacAllowedAlgorithms, which
// limits the algorithms request signing accepts.
func (s *OAS) CertificateReferences(hmacAllowedAlgorithms []string) apidef.CertificateReferences {
	var refs apidef.CertificateReferences

	ext := s.GetTykExtension()
	if ext == nil {
		return refs
	}

	upstream, server := ext.Upstream, ext.Server

	if p := upstream.CertificatePinning; p != nil {
		for _, k := range p.DomainToPublicKeysMapping {
			refs.Add(apidef.CertificateUsePinned, p.Enabled, k.PublicKeys...)
		}
	}

	if m := upstream.MutualTLS; m != nil {
		for _, d := range m.DomainToCertificates {
			refs.Add(apidef.CertificateUseUpstream, m.Enabled, d.Certificate)
		}
	}

	if cc := server.ClientCertificates; cc != nil {
		refs.Add(apidef.CertificateUseClient, cc.Enabled, cc.Allowlist...)
	}

	if d := server.CustomDomain; d != nil {
		refs.Add(apidef.CertificateUseServer, d.Enabled, d.Certificates...)
	}

	if a := upstream.Authentication; a != nil && a.RequestSigning != nil {
		rs := a.RequestSigning
		refs.Add(apidef.CertificateUseRequestSigning, rs.Enabled && apidef.RequestSigningUsesCertificate(rs.Algorithm, rs.KeyID, hmacAllowedAlgorithms), rs.CertificateID)
	}

	refs = append(refs, tokenExchangeReferences(server.Authentication)...)

	return refs
}

// tokenExchangeReferences lists the certificates that token exchange providers authenticate with.
// The Gateway runs token exchange only when server.authentication, the scheme and its tokenExchange
// block are all enabled, and uses certId only with private_key_jwt. It reads a single OAuth2 scheme,
// chosen in map order when there are several, so every scheme counts here.
func tokenExchangeReferences(auth *Authentication) apidef.CertificateReferences {
	var refs apidef.CertificateReferences
	if auth == nil {
		return refs
	}

	for _, s := range auth.SecuritySchemes {
		// asOAuth2Scheme converts an untyped entry as GetTykOAuth2Config does, without storing it back.
		scheme := asOAuth2Scheme(s)
		if scheme == nil || scheme.TokenExchange == nil {
			continue
		}

		te := scheme.TokenExchange
		for _, p := range te.Providers {
			if p.ClientAuth == nil {
				continue
			}

			inUse := auth.Enabled && scheme.Enabled && te.Enabled && p.ClientAuth.Method == OAuth2ClientAuthPrivateKeyJWT
			refs.Add(apidef.CertificateUseTokenExchange, inUse, p.ClientAuth.CertID)
		}
	}

	return refs
}
