package oas

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
)

func TestUpstream(t *testing.T) {
	var emptyUpstream Upstream

	var convertedAPI apidef.APIDefinition
	emptyUpstream.ExtractTo(&convertedAPI)

	var resultUpstream Upstream
	resultUpstream.Fill(convertedAPI)

	assert.Equal(t, emptyUpstream, resultUpstream)
}

func TestServiceDiscovery(t *testing.T) {
	var emptyServiceDiscovery ServiceDiscovery

	var convertedServiceDiscovery apidef.ServiceDiscoveryConfiguration
	emptyServiceDiscovery.ExtractTo(&convertedServiceDiscovery)

	var resultServiceDiscovery ServiceDiscovery
	resultServiceDiscovery.Fill(convertedServiceDiscovery)

	assert.Equal(t, emptyServiceDiscovery, resultServiceDiscovery)
}

func TestTest(t *testing.T) {
	var emptyTest Test

	var convertedTest apidef.UptimeTests
	emptyTest.ExtractTo(&convertedTest)

	var resultTest Test
	resultTest.Fill(convertedTest)

	assert.Equal(t, emptyTest, resultTest)
}

func TestUpstreamMutualTLS(t *testing.T) {
	t.Parallel()
	t.Run("extractTo api definition", func(t *testing.T) {
		t.Parallel()
		testcases := []struct {
			title       string
			input       MutualTLS
			expectValue apidef.APIDefinition
		}{
			{
				"enabled=false, domain to certs nil",
				MutualTLS{Enabled: false, DomainToCertificates: nil},
				apidef.APIDefinition{
					UpstreamCertificatesDisabled: true,
				},
			},
			{
				"enabled=false, valid domain to cert mapping",
				MutualTLS{Enabled: false, DomainToCertificates: []DomainToCertificate{
					{Domain: "example.org", Certificate: "cert-1"},
					{Domain: "example.com", Certificate: "cert-2"},
				}},
				apidef.APIDefinition{
					UpstreamCertificatesDisabled: true,
					UpstreamCertificates: map[string]string{
						"example.org": "cert-1",
						"example.com": "cert-2",
					},
				},
			},
			{
				"enabled=true, valid domain to cert mapping",
				MutualTLS{Enabled: true, DomainToCertificates: []DomainToCertificate{
					{Domain: "example.org", Certificate: "cert-1"},
					{Domain: "example.com", Certificate: "cert-2"},
				}},
				apidef.APIDefinition{
					UpstreamCertificatesDisabled: false,
					UpstreamCertificates: map[string]string{
						"example.org": "cert-1",
						"example.com": "cert-2",
					},
				},
			},
			{
				"enabled=true, empty domain to cert mapping",
				MutualTLS{Enabled: true, DomainToCertificates: nil},
				apidef.APIDefinition{},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.title, func(t *testing.T) {
				var apiDef apidef.APIDefinition

				tc.input.ExtractTo(&apiDef)

				assert.Equal(t, tc.expectValue, apiDef)
			})
		}
	})
	t.Run("fillFrom api definition", func(t *testing.T) {
		t.Parallel()
		testcases := []struct {
			title         string
			input         apidef.APIDefinition
			expectedValue MutualTLS
		}{
			{
				"disabled=false, empty domain to cert mapping",
				apidef.APIDefinition{UpstreamCertificatesDisabled: false},
				MutualTLS{
					Enabled: true,
				},
			},
			{
				"disabled=true, empty domain to cert mapping",
				apidef.APIDefinition{UpstreamCertificatesDisabled: true},
				MutualTLS{
					Enabled: false,
				},
			},
			{
				"disabled=false, valid domain to cert mapping",
				apidef.APIDefinition{UpstreamCertificatesDisabled: false,
					UpstreamCertificates: map[string]string{
						"example.org": "cert-1",
						"example.com": "cert-2",
					}},
				MutualTLS{
					Enabled: true,
					DomainToCertificates: []DomainToCertificate{
						{
							Domain:      "example.org",
							Certificate: "cert-1",
						},
						{
							Domain:      "example.com",
							Certificate: "cert-2",
						},
					},
				},
			},
			{
				"disabled=true, valid domain to cert mapping",
				apidef.APIDefinition{UpstreamCertificatesDisabled: true,
					UpstreamCertificates: map[string]string{
						"example.org": "cert-1",
						"example.com": "cert-2",
					}},
				MutualTLS{
					Enabled: false,
					DomainToCertificates: []DomainToCertificate{
						{
							Domain:      "example.org",
							Certificate: "cert-1",
						},
						{
							Domain:      "example.com",
							Certificate: "cert-2",
						},
					},
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.title, func(t *testing.T) {
				var mutualTLS MutualTLS

				mutualTLS.Fill(tc.input)

				assert.Equal(t, tc.expectedValue.Enabled, mutualTLS.Enabled)
				assert.ElementsMatch(t, tc.expectedValue.DomainToCertificates, mutualTLS.DomainToCertificates)
			})
		}
	})
}
