package apidef

import (
	"slices"
	"strings"
)

// CertificateUseType is one way an API can use a certificate.
type CertificateUseType string

const (
	CertificateUseClient         CertificateUseType = "client"
	CertificateUseUpstream       CertificateUseType = "upstream"
	CertificateUseServer         CertificateUseType = "server"
	CertificateUsePinned         CertificateUseType = "pinned"
	CertificateUseRequestSigning CertificateUseType = "request_signing"
	CertificateUseTokenExchange  CertificateUseType = "token_exchange" // Tyk OAS only
)

// RequestSigningAlgorithms are the algorithms the Gateway can sign upstream requests with.
var RequestSigningAlgorithms = []string{"hmac-sha1", "hmac-sha256", "hmac-sha384", "hmac-sha512", "rsa-sha256"}

// CertificateReference is one place in an API definition that names a certificate.
// InUse is true when that setting is switched on and uses the certificate, whatever the API's state.
type CertificateReference struct {
	CertID string
	Type   CertificateUseType
	InUse  bool
}

// Active reports whether the reference is a use the Gateway acts on: the API is active,
// the setting is switched on and it uses the certificate.
func (r CertificateReference) Active(apiActive bool) bool {
	return apiActive && r.InUse
}

// CertificateReferences collects certificate references.
type CertificateReferences []CertificateReference

// Add records a reference for each non-empty certificate ID.
func (r *CertificateReferences) Add(t CertificateUseType, inUse bool, certIDs ...string) {
	for _, id := range certIDs {
		if id != "" {
			*r = append(*r, CertificateReference{CertID: id, Type: t, InUse: inUse})
		}
	}
}

// AddPinnedPublicKeys records each key in a pinning value. The Gateway splits
// values on "," without trimming them.
func (r *CertificateReferences) AddPinnedPublicKeys(inUse bool, keys string) {
	r.Add(CertificateUsePinned, inUse, strings.Split(keys, ",")...)
}

// CertificateUse is one way an API uses a certificate, and whether that use is active.
type CertificateUse struct {
	Type   CertificateUseType `json:"type"`
	Active bool               `json:"active"`
}

// Uses lists each way the references use the certificate, once per type, in the order first referenced.
// A type is active when any of its references is.
func (r CertificateReferences) Uses(certID string, apiActive bool) []CertificateUse {
	var uses []CertificateUse
	for _, ref := range r {
		if ref.CertID != certID {
			continue
		}

		active := ref.Active(apiActive)
		if i := slices.IndexFunc(uses, func(u CertificateUse) bool { return u.Type == ref.Type }); i >= 0 {
			uses[i].Active = uses[i].Active || active
			continue
		}
		uses = append(uses, CertificateUse{Type: ref.Type, Active: active})
	}
	return uses
}

// RequestSigningUsesCertificate reports whether the Gateway signs with the certificate. It needs
// a key ID, accepts only the allowed algorithms (or RequestSigningAlgorithms when none are set),
// and reads the certificate only for rsa-* algorithms.
func RequestSigningUsesCertificate(algorithm, keyID string, allowedAlgorithms []string) bool {
	if len(allowedAlgorithms) == 0 {
		allowedAlgorithms = RequestSigningAlgorithms
	}
	return keyID != "" && strings.HasPrefix(algorithm, "rsa") && slices.Contains(allowedAlgorithms, algorithm)
}

// CertificateReferences lists every place a Tyk Classic API definition names a certificate.
// Tyk OAS APIs should use (*oas.OAS).CertificateReferences, which also covers token exchange.
func (a *APIDefinition) CertificateReferences() CertificateReferences {
	var refs CertificateReferences

	refs.Add(CertificateUseClient, a.UseMutualTLSAuth, a.ClientCertificates...)

	for _, id := range a.UpstreamCertificates {
		refs.Add(CertificateUseUpstream, !a.UpstreamCertificatesDisabled, id)
	}

	refs.Add(CertificateUseServer, !a.DomainDisabled, a.Certificates...)

	for _, keys := range a.PinnedPublicKeys {
		refs.AddPinnedPublicKeys(!a.CertificatePinningDisabled, keys)
	}

	rs := a.RequestSigning
	refs.Add(CertificateUseRequestSigning, rs.IsEnabled && RequestSigningUsesCertificate(rs.Algorithm, rs.KeyId, a.HmacAllowedAlgorithms), rs.CertificateId)

	return refs
}
