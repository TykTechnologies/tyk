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
	store                      storage.Handler // Redis storage for cooldowns
	expiryCheckContext         context.Context
	expiryCheckCancelFunc      context.CancelFunc
	expiryCheckBatcher         certcheck.BackgroundBatcher
	upstreamExpiryCheckBatcher certcheck.BackgroundBatcher
}

func (m *CertificateCheckMW) Name() string {
	return "CertificateCheckMW"
}

func (m *CertificateCheckMW) EnabledForSpec() bool {
	return m.Spec.UseMutualTLSAuth || !m.Spec.UpstreamCertificatesDisabled
}

func (m *CertificateCheckMW) Init() {
	// Initialize Redis store for cooldowns if not already done
	if m.store == nil {
		log.
			WithField("api_id", m.Spec.APIID).
			WithField("api_name", m.Spec.Name).
			WithField("mw", m.Name()).
			Debug("Initializing Redis store for cooldowns.")

		m.store = &storage.RedisCluster{
			KeyPrefix:         "cert-cooldown:",
			ConnectionHandler: m.Gw.StorageConnectionHandler,
		}

		m.store.Connect()
	}

	// Initialize expiry check batcher
	if m.expiryCheckBatcher == nil {
		log.
			WithField("api_id", m.Spec.APIID).
			WithField("api_name", m.Spec.Name).
			WithField("mw", m.Name()).
			Debug("Initializing certificate expiry check batcher.")

		apiData := certcheck.APIMetaData{
			APIID:   m.Spec.APIID,
			APIName: m.Spec.Name,
		}

		var err error
		m.expiryCheckBatcher, err = certcheck.NewCertificateExpiryCheckBatcherWithRole(
			m.logger,
			apiData,
			m.Gw.GetConfig().Security.CertificateExpiryMonitor,
			m.store,
			m.Gw.FireSystemEvent,
			"client",
		)

		if err != nil {
			log.
				WithField("api_id", m.Spec.APIID).
				WithField("api_name", m.Spec.Name).
				WithField("mw", m.Name()).
				Error("Failed to initialize certificate expiry check batcher.")
			return
		}
	}

	m.expiryCheckContext, m.expiryCheckCancelFunc = context.WithCancel(context.Background())
	go m.expiryCheckBatcher.RunInBackground(m.expiryCheckContext)

	// Initialize upstream certificate expiry check batcher
	if m.upstreamExpiryCheckBatcher == nil && !m.Spec.UpstreamCertificatesDisabled {
		log.
			WithField("api_id", m.Spec.APIID).
			WithField("api_name", m.Spec.Name).
			WithField("mw", m.Name()).
			Debug("Initializing upstream certificate expiry check batcher.")

		apiData := certcheck.APIMetaData{
			APIID:   m.Spec.APIID,
			APIName: m.Spec.Name,
		}

		var err error
		m.upstreamExpiryCheckBatcher, err = certcheck.NewCertificateExpiryCheckBatcherWithRole(
			m.logger,
			apiData,
			m.Gw.GetConfig().Security.CertificateExpiryMonitor,
			m.store,
			m.Gw.FireSystemEvent,
			"upstream",
		)

		if err != nil {
			log.
				WithField("api_id", m.Spec.APIID).
				WithField("api_name", m.Spec.Name).
				WithField("mw", m.Name()).
				Error("Failed to initialize upstream certificate expiry check batcher.")
		} else {
			go m.upstreamExpiryCheckBatcher.RunInBackground(m.expiryCheckContext)
			go m.periodicUpstreamCertificateCheck() // Start periodic checking
		}
	}
}

func (m *CertificateCheckMW) Unload() {
	if m.expiryCheckCancelFunc != nil {
		log.
			WithField("api_id", m.Spec.APIID).
			WithField("api_name", m.Spec.Name).
			WithField("mw", m.Name()).
			Debug("Stopping certificate expiry check batcher.")

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
			log.
				WithField("api_id", m.Spec.APIID).
				WithField("api_name", m.Spec.Name).
				WithField("mw", m.Name()).
				Warning("Certificate validation failed: ", err)
			m.batchCertificatesExpirationCheck(apiCerts)
			return err, http.StatusForbidden
		}

		m.batchCertificatesExpirationCheck(apiCerts)
	}

	return nil, http.StatusOK
}

// batchCertificatesExpirationCheck batches certificates for expiry checking using the configured BackgroundBatcher.
func (m *CertificateCheckMW) batchCertificatesExpirationCheck(certificates []*tls.Certificate) {
	log.
		WithField("api_id", m.Spec.APIID).
		WithField("api_name", m.Spec.Name).
		WithField("mw", m.Name()).
		Debugf("Batch certificates for expiration check with %d certificates", len(certificates))

	for _, cert := range certificates {
		certInfo, ok := m.extractCertInfo(cert)
		if !ok {
			continue
		}

		err := m.expiryCheckBatcher.Add(certInfo)
		if err != nil {
			log.
				WithField("api_id", m.Spec.APIID).
				WithField("api_name", m.Spec.Name).
				WithField("mw", m.Name()).
				Error("[CertificateCheckMW] Failed to batch certificate expiry check: ", err)
		}
	}
}

// extractCertInfo validates the certificate and extracts basic information.
func (m *CertificateCheckMW) extractCertInfo(cert *tls.Certificate) (certInfo certcheck.CertInfo, ok bool) {
	if cert == nil || cert.Leaf == nil {
		log.
			WithField("api_id", m.Spec.APIID).
			WithField("api_name", m.Spec.Name).
			WithField("mw", m.Name()).
			Warning("Extract Cert Info: Skipping invalid certificate")
		return certcheck.CertInfo{}, false
	}

	certID := crypto.HexSHA256(cert.Leaf.Raw)
	if certID == "" {
		log.
			WithField("api_id", m.Spec.APIID).
			WithField("api_name", m.Spec.Name).
			WithField("mw", m.Name()).
			Warning("Extract Cert Info: Skipping certificate with empty ID (no raw data)")
		return certcheck.CertInfo{}, false
	}

	return certcheck.CertInfo{
		ID:          certID,
		CommonName:  cert.Leaf.Subject.CommonName,
		NotAfter:    cert.Leaf.NotAfter,
		UntilExpiry: time.Until(cert.Leaf.NotAfter),
	}, true
}

// CheckUpstreamCertificates checks the expiry status of upstream certificates
func (m *CertificateCheckMW) CheckUpstreamCertificates() {
	if m.upstreamExpiryCheckBatcher == nil || m.Spec.UpstreamCertificatesDisabled {
		return
	}

	// Collect certificate IDs from global and API-specific config
	certIDs := []string{}
	gwConfig := m.Gw.GetConfig()

	// Add global upstream certificates (extract values from map)
	for _, certID := range gwConfig.Security.Certificates.Upstream {
		certIDs = append(certIDs, certID)
	}

	// Add API-specific upstream certificates (extract values from map)
	if m.Spec.UpstreamCertificates != nil {
		for _, certID := range m.Spec.UpstreamCertificates {
			certIDs = append(certIDs, certID)
		}
	}

	if len(certIDs) == 0 {
		return
	}

	// Load and check certificates
	certificates := m.Gw.CertificateManager.List(certIDs, certs.CertificatePrivate)
	checked := 0
	for _, cert := range certificates {
		if certInfo, ok := m.extractCertInfo(cert); ok {
			if err := m.upstreamExpiryCheckBatcher.Add(certInfo); err != nil {
				log.
					WithField("api_id", m.Spec.APIID).
					WithField("api_name", m.Spec.Name).
					WithField("mw", m.Name()).
					WithError(err).
					Warning("Failed to add upstream certificate to expiry check batch")
			}
			checked++
		}
	}

	if checked > 0 {
		log.
			WithField("api_id", m.Spec.APIID).
			WithField("api_name", m.Spec.Name).
			WithField("mw", m.Name()).
			WithField("count", checked).
			Debug("Checked upstream certificates for expiry")
	}
}

// periodicUpstreamCertificateCheck starts periodic checking of upstream certificates
func (m *CertificateCheckMW) periodicUpstreamCertificateCheck() {
	// Check immediately on startup
	m.CheckUpstreamCertificates()

	// Use check cooldown interval for periodic checking
	intervalSeconds := m.Gw.GetConfig().Security.CertificateExpiryMonitor.CheckCooldownSeconds

	// If 0, disable periodic checking
	if intervalSeconds <= 0 {
		log.
			WithField("api_id", m.Spec.APIID).
			WithField("api_name", m.Spec.Name).
			WithField("mw", m.Name()).
			Info("Periodic upstream certificate checking disabled (check_cooldown_seconds = 0)")
		return
	}

	log.
		WithField("api_id", m.Spec.APIID).
		WithField("api_name", m.Spec.Name).
		WithField("mw", m.Name()).
		WithField("interval_seconds", intervalSeconds).
		Info("Starting periodic upstream certificate checking")

	ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.expiryCheckContext.Done():
			log.
				WithField("api_id", m.Spec.APIID).
				WithField("api_name", m.Spec.Name).
				WithField("mw", m.Name()).
				Debug("Periodic upstream certificate checking stopped")
			return
		case <-ticker.C:
			m.CheckUpstreamCertificates()
		}
	}
}
