package main

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"

	"github.com/gorilla/mux"
)

type APICertificateStatusMessage struct {
	CertID  string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type APIAllCertificates struct {
	CertIDs []string `json:"certs"`
}

// dummyGetCertificate needed because TLSConfig require setting Certificates array or GetCertificate function from start, even if it get overriden by `getTLSConfigForClient`
func dummyGetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, nil
}

func getTLSConfigForClient(baseConfig *tls.Config, listenPort int) func(hello *tls.ClientHelloInfo) (*tls.Config, error) {

	// Supporting legacy certificate configuration
	serverCerts := []tls.Certificate{}
	certNameMap := map[string]*tls.Certificate{}

	for _, certData := range config.Global.HttpServerOptions.Certificates {
		cert, err := tls.LoadX509KeyPair(certData.CertFile, certData.KeyFile)
		if err != nil {
			log.Errorf("Server error: loadkeys: %s", err)
			continue
		}
		serverCerts = append(serverCerts, cert)
		certNameMap[certData.Name] = &cert
	}

	for _, cert := range CertificateManager.List(config.Global.HttpServerOptions.SSLCertificates, certs.CertificatePrivate) {
		serverCerts = append(serverCerts, *cert)
	}

	baseConfig.Certificates = serverCerts

	baseConfig.BuildNameToCertificate()
	for name, cert := range certNameMap {
		baseConfig.NameToCertificate[name] = cert
	}

	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		newConfig := baseConfig.Clone()

		isControlAPI := (listenPort != 0 && config.Global.ControlAPIPort == listenPort) || (config.Global.ControlAPIHostname == hello.ServerName)

		if isControlAPI && config.Global.Security.ControlAPIUseMutualTLS {
			newConfig.ClientAuth = tls.RequireAndVerifyClientCert
			newConfig.ClientCAs = CertificateManager.CertPool(config.Global.Security.Certificates.ControlAPI)

			return newConfig, nil
		}

		for _, spec := range apiSpecs {
			if spec.UseMutualTLSAuth && spec.Domain == hello.ServerName {
				newConfig.ClientAuth = tls.RequireAndVerifyClientCert
				certIDs := append(spec.ClientCertificates, config.Global.Security.Certificates.API...)
				newConfig.ClientCAs = CertificateManager.CertPool(certIDs)
				break
			}
		}

		return newConfig, nil
	}
}

func certHandler(w http.ResponseWriter, r *http.Request) {
	certID := mux.Vars(r)["certID"]

	switch r.Method {
	case "POST":
		content, err := ioutil.ReadAll(r.Body)
		if err != nil {
			doJSONWrite(w, 405, apiError("Malformed request body"))
			return
		}

		orgID := r.URL.Query().Get("org_id")
		var certID string
		if certID, err = CertificateManager.Add(content, orgID); err != nil {
			doJSONWrite(w, 403, apiError(err.Error()))
			return
		}

		doJSONWrite(w, 200, &APICertificateStatusMessage{certID, "ok", "Certificate added"})
	case "GET":
		if certID == "" {
			certIds := CertificateManager.ListAllIds()
			doJSONWrite(w, 200, &APIAllCertificates{certIds})
			return
		}

		certIDs := strings.Split(certID, ",")
		certificates := CertificateManager.List(certIDs, certs.CertificateAny)

		if len(certIDs) == 1 {
			if len(certificates) == 0 {
				doJSONWrite(w, 404, apiError("Certificate with given SHA256 fingerprint not found"))
				return
			}

			doJSONWrite(w, 200, certs.ExtractCertificateMeta(certificates[0]))
			return
		} else {
			var meta []certs.CertificateMeta
			for _, cert := range certificates {
				meta = append(meta, certs.ExtractCertificateMeta(cert))
			}

			doJSONWrite(w, 200, meta)
			return
		}
	case "DELETE":
		CertificateManager.Delete(certID)
		doJSONWrite(w, 200, &APIStatusMessage{"ok", "removed"})
	}
}
