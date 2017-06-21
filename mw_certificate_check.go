package main

import (
	"net/http"
)

// CertificateCheckMW is used if domain was not detected or multiple APIs bind on the same domain. In this case authentification check happens not on TLS side but on HTTP level using this middleware
type CertificateCheckMW struct {
	BaseMiddleware
}

func (m *CertificateCheckMW) Name() string {
	return "CertificateCheckMW"
}

func (m *CertificateCheckMW) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if m.Spec.UseMutualTLSAuth {
		if err := CertificateManager.ValidateRequestCertificate(m.Spec.ClientCertificates, r); err != nil {
			return err, 403
		}
	}
	return nil, 200
}
