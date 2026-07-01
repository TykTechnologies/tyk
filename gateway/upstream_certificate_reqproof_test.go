package gateway

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/crypto"
)

// Verifies: STK-REQ-105, SYS-REQ-193, SW-REQ-181
// STK-REQ-105:STK-REQ-105-AC-01:acceptance
// STK-REQ-105:nominal:nominal
// STK-REQ-105:boundary:nominal
// STK-REQ-105:determinism:nominal
// SYS-REQ-193:nominal:nominal
// SYS-REQ-193:boundary:nominal
// SYS-REQ-193:determinism:nominal
// SW-REQ-181:nominal:nominal
// SW-REQ-181:boundary:nominal
// SW-REQ-181:determinism:nominal
// MCDC SYS-REQ-193: gateway_upstream_certificate_selection_operation_terminal=T => TRUE
// MCDC SW-REQ-181: gateway_upstream_certificate_selection_operation_terminal=T => TRUE
func TestGatewayUpstreamCertificateSelectionReqProof(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	_, _, combinedClientPEM, _ := crypto.GenCertificate(&x509.Certificate{}, false)
	certID, err := ts.Gw.CertificateManager.Add(combinedClientPEM, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		ts.Gw.CertificateManager.Delete(certID, "")
	})

	certMaps := []map[string]string{
		{"*": "fallback-cert-id"},
		{"*.example.com": "subdomain-cert-id", "api.example.com:8443": certID},
	}
	assert.Equal(t, certID, getCertificateIDForHost("api.example.com:8443", certMaps))
	assert.Equal(t, "subdomain-cert-id", getCertificateIDForHost("admin.example.com:8443", certMaps))
	assert.Equal(t, "", getCertificateIDForHost("unmatched.local", []map[string]string{{}}))

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			UpstreamCertificates: map[string]string{
				"api.example.com:8443": certID,
			},
		},
	}
	assert.NotNil(t, ts.Gw.getUpstreamCertificate("api.example.com:8443", spec))
	assert.Nil(t, ts.Gw.getUpstreamCertificate("unmatched.local", spec))
}
