package apidef

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const certRefsTestCertID = "org1cert"

func TestAPIDefinition_CertificateReferences(t *testing.T) {
	use := func(t CertificateUseType, active bool) CertificateUse {
		return CertificateUse{Type: t, Active: active}
	}

	tests := []struct {
		name   string
		mutate func(a *APIDefinition)
		want   []CertificateUse
	}{
		{
			name:   "no reference",
			mutate: func(a *APIDefinition) { a.ClientCertificates = []string{"other"} },
			want:   nil,
		},
		{
			name: "every use switched on",
			mutate: func(a *APIDefinition) {
				a.UseMutualTLSAuth = true
				a.ClientCertificates = []string{certRefsTestCertID}
				a.UpstreamCertificates = map[string]string{"*": certRefsTestCertID}
				a.Certificates = []string{certRefsTestCertID}
				a.PinnedPublicKeys = map[string]string{"*": certRefsTestCertID}
				a.RequestSigning = RequestSigningMeta{IsEnabled: true, Algorithm: "rsa-sha256", KeyId: "key", CertificateId: certRefsTestCertID}
			},
			want: []CertificateUse{
				use(CertificateUseClient, true),
				use(CertificateUseUpstream, true),
				use(CertificateUseServer, true),
				use(CertificateUsePinned, true),
				use(CertificateUseRequestSigning, true),
			},
		},
		{
			name: "every use switched off",
			mutate: func(a *APIDefinition) {
				a.ClientCertificates = []string{certRefsTestCertID}
				a.UpstreamCertificates = map[string]string{"*": certRefsTestCertID}
				a.UpstreamCertificatesDisabled = true
				a.Certificates = []string{certRefsTestCertID}
				a.DomainDisabled = true
				a.PinnedPublicKeys = map[string]string{"*": certRefsTestCertID}
				a.CertificatePinningDisabled = true
				a.RequestSigning = RequestSigningMeta{Algorithm: "rsa-sha256", KeyId: "key", CertificateId: certRefsTestCertID}
			},
			want: []CertificateUse{
				use(CertificateUseClient, false),
				use(CertificateUseUpstream, false),
				use(CertificateUseServer, false),
				use(CertificateUsePinned, false),
				use(CertificateUseRequestSigning, false),
			},
		},
		{
			name: "deactivated API",
			mutate: func(a *APIDefinition) {
				a.Active = false
				a.UseMutualTLSAuth = true
				a.ClientCertificates = []string{certRefsTestCertID}
				a.Certificates = []string{certRefsTestCertID}
			},
			want: []CertificateUse{use(CertificateUseClient, false), use(CertificateUseServer, false)},
		},
		{
			name: "pin list with several keys",
			mutate: func(a *APIDefinition) {
				a.PinnedPublicKeys = map[string]string{"example.com": "other," + certRefsTestCertID}
			},
			want: []CertificateUse{use(CertificateUsePinned, true)},
		},
		{
			name: "pin list entries are not trimmed",
			mutate: func(a *APIDefinition) {
				a.PinnedPublicKeys = map[string]string{"example.com": "other, " + certRefsTestCertID}
			},
			want: nil,
		},
		{
			name: "same use referencing the certificate twice",
			mutate: func(a *APIDefinition) {
				a.UpstreamCertificates = map[string]string{"a.example.com": certRefsTestCertID, "b.example.com": certRefsTestCertID}
			},
			want: []CertificateUse{use(CertificateUseUpstream, true)},
		},
		{
			name: "request signing with an hmac algorithm",
			mutate: func(a *APIDefinition) {
				a.RequestSigning = RequestSigningMeta{IsEnabled: true, Algorithm: "hmac-sha256", KeyId: "key", CertificateId: certRefsTestCertID}
			},
			want: []CertificateUse{use(CertificateUseRequestSigning, false)},
		},
		{
			name: "request signing with an rsa algorithm the Gateway does not support",
			mutate: func(a *APIDefinition) {
				a.RequestSigning = RequestSigningMeta{IsEnabled: true, Algorithm: "rsa-sha512", KeyId: "key", CertificateId: certRefsTestCertID}
			},
			want: []CertificateUse{use(CertificateUseRequestSigning, false)},
		},
		{
			name: "request signing with an rsa algorithm in hmac_allowed_algorithms",
			mutate: func(a *APIDefinition) {
				a.HmacAllowedAlgorithms = []string{"rsa-sha512"}
				a.RequestSigning = RequestSigningMeta{IsEnabled: true, Algorithm: "rsa-sha512", KeyId: "key", CertificateId: certRefsTestCertID}
			},
			want: []CertificateUse{use(CertificateUseRequestSigning, true)},
		},
		{
			name: "request signing with an algorithm missing from hmac_allowed_algorithms",
			mutate: func(a *APIDefinition) {
				a.HmacAllowedAlgorithms = []string{"hmac-sha256"}
				a.RequestSigning = RequestSigningMeta{IsEnabled: true, Algorithm: "rsa-sha256", KeyId: "key", CertificateId: certRefsTestCertID}
			},
			want: []CertificateUse{use(CertificateUseRequestSigning, false)},
		},
		{
			name: "request signing without a key ID",
			mutate: func(a *APIDefinition) {
				a.RequestSigning = RequestSigningMeta{IsEnabled: true, Algorithm: "rsa-sha256", CertificateId: certRefsTestCertID}
			},
			want: []CertificateUse{use(CertificateUseRequestSigning, false)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			api := &APIDefinition{Active: true}
			tc.mutate(api)

			assert.Equal(t, tc.want, api.CertificateReferences().Uses(certRefsTestCertID, api.Active))
		})
	}

	t.Run("lists every certificate ID", func(t *testing.T) {
		api := &APIDefinition{
			ClientCertificates:   []string{"client"},
			UpstreamCertificates: map[string]string{"*": "upstream"},
			Certificates:         []string{"server", ""},
			PinnedPublicKeys:     map[string]string{"example.com": "pin-a,pin-b"},
			RequestSigning:       RequestSigningMeta{Algorithm: "hmac-sha256", CertificateId: "signing"},
		}

		var ids []string
		for _, r := range api.CertificateReferences() {
			ids = append(ids, r.CertID)
		}
		assert.ElementsMatch(t, []string{"client", "upstream", "server", "pin-a", "pin-b", "signing"}, ids)
	})
}
