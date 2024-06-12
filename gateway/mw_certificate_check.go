package gateway

import (
	"crypto/tls"
	"net/http"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/internal/crypto"
)

// CertificateCheckMW is used if domain was not detected or multiple APIs bind on the same domain. In this case authentification check happens not on TLS side but on HTTP level using this middleware
type CertificateCheckMW struct {
	clientCerts []*tls.Certificate
	*BaseMiddleware
}

func (m *CertificateCheckMW) Name() string {
	return "CertificateCheckMW"
}

func (m *CertificateCheckMW) EnabledForSpec() bool {
	if !m.Spec.UseMutualTLSAuth {
		return false
	}

	certIDs := append(m.Spec.ClientCertificates, m.Spec.GlobalConfig.Security.Certificates.API...)
	apiCerts := m.Gw.CertificateManager.List(certIDs, certs.CertificatePublic)
	m.clientCerts = make([]*tls.Certificate, 0)
	for _, cert := range apiCerts {
		if !cert.Leaf.IsCA {
			m.clientCerts = append(m.clientCerts, cert)
		}
	}

	return len(m.clientCerts) > 0
}

func (m *CertificateCheckMW) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	if err := crypto.ValidateRequestCerts(r, m.clientCerts); err != nil {
		return err, http.StatusForbidden
	}

	return nil, http.StatusOK
}
