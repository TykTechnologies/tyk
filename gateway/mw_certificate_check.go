package gateway

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/internal/certcheck"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/storage"
)

// CertificateCheckMW is used if domain was not detected or multiple APIs bind on the same domain. In this case authentification check happens not on TLS side but on HTTP level using this middleware
type CertificateCheckMW struct {
	*BaseMiddleware
	store                 storage.Handler // Redis storage for cooldowns
	expiryCheckContext    context.Context
	expiryCheckCancelFunc context.CancelFunc
	expiryCheckBatcher    certcheck.BackgroundBatcher
}

func (m *CertificateCheckMW) Name() string {
	return "CertificateCheckMW"
}

func (m *CertificateCheckMW) EnabledForSpec() bool {
	return m.Spec.UseMutualTLSAuth
}

func (m *CertificateCheckMW) Init() {
	// Initialize Redis store for cooldowns if not already done
	if m.store == nil {
		log.Debug("[CertificateCheckMW] Initializing Redis store for cooldowns.")

		m.store = &storage.RedisCluster{
			KeyPrefix:         "cert-cooldown:",
			ConnectionHandler: m.Gw.StorageConnectionHandler,
		}

		m.store.Connect()
	}

	// Initialize expiry check batcher
	if m.expiryCheckBatcher == nil {
		log.Debug("[CertificateCheckMW] Initializing certificate expiry check batcher.")

		var err error
		m.expiryCheckBatcher, err = certcheck.NewCertificateExpiryCheckBatcher(
			m.logger,
			m.Gw.GetConfig().Security.CertificateExpiryMonitor,
			m.store,
			m.Spec.FireEvent,
		)

		if err != nil {
			log.Fatal("[CertificateCheckMW] Failed to initialize certificate expiry check batcher.")
			return
		}
	}

	m.expiryCheckContext, m.expiryCheckCancelFunc = context.WithCancel(context.Background())
	go m.expiryCheckBatcher.RunInBackground(m.expiryCheckContext)
}

func (m *CertificateCheckMW) Unload() {
	if m.expiryCheckCancelFunc != nil {
		m.expiryCheckCancelFunc()
	}
}

func (m *CertificateCheckMW) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if r == nil {
		return nil, http.StatusOK
	}

	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	if m.Spec.UseMutualTLSAuth {
		certIDs := append(m.Spec.ClientCertificates, m.Spec.GlobalConfig.Security.Certificates.API...)
		apiCerts := m.Gw.CertificateManager.List(certIDs, certs.CertificatePublic)
		if err := crypto.ValidateRequestCerts(r, apiCerts); err != nil {
			log.Warning("[CertificateCheckMW] Certificate validation failed: ", err)

			return err, http.StatusForbidden
		}

		log.Debug("[CertificateCheckMW] Starting certificate expiration check for API: ", m.Spec.APIID, " with ", len(apiCerts), " certificates")
		m.batchCertificatesExpiration(apiCerts)
	}

	return nil, http.StatusOK
}

// batchCertificatesExpiration batches certificates for expiry checking using the configured BackgroundBatcher.
func (m *CertificateCheckMW) batchCertificatesExpiration(certificates []*tls.Certificate) {
	for _, cert := range certificates {
		certInfo, ok := m.extractCertInfo(cert)
		if !ok {
			continue
		}

		err := m.expiryCheckBatcher.Add(certInfo)
		if err != nil {
			log.Error("[CertificateCheckMW] Failed to batch certificate expiry check: ", err)
		}
	}
}

// extractCertInfo validates the certificate and extracts basic information.
func (m *CertificateCheckMW) extractCertInfo(cert *tls.Certificate) (certInfo certcheck.CertInfo, ok bool) {
	if cert == nil || cert.Leaf == nil {
		log.Warning("[CertificateCheckMW] Skipping invalid certificate")
		return certcheck.CertInfo{}, false
	}

	certID := crypto.HexSHA256(cert.Leaf.Raw)
	if certID == "" {
		log.Warning("[CertificateCheckMW] Skipping certificate with empty ID (no raw data)")
		return certcheck.CertInfo{}, false
	}

	return certcheck.CertInfo{
		ID:               certID,
		CommonName:       cert.Leaf.Subject.CommonName,
		NotAfter:         cert.Leaf.NotAfter,
		HoursUntilExpiry: int(time.Until(cert.Leaf.NotAfter).Hours()),
	}, true
}
