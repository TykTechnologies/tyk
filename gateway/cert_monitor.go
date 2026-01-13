package gateway

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/certcheck"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/storage"
)

// GlobalCertificateMonitor monitors expiry for Gateway-level certificates
// (server certificates and CA certificates). These are not tied to specific APIs.
type GlobalCertificateMonitor struct {
	gw                *Gateway
	serverCertBatcher certcheck.BackgroundBatcher
	caCertBatcher     certcheck.BackgroundBatcher
	store             storage.Handler
	ctx               context.Context
	cancelFunc        context.CancelFunc
	logger            *logrus.Entry
}

// NewGlobalCertificateMonitor creates a new global certificate monitor
func NewGlobalCertificateMonitor(gw *Gateway) (*GlobalCertificateMonitor, error) {
	logger := log.WithField("component", "GlobalCertificateMonitor")

	// Initialize Redis store for cooldowns
	store := &storage.RedisCluster{
		KeyPrefix:         "cert-cooldown:",
		ConnectionHandler: gw.StorageConnectionHandler,
	}

	store.Connect()

	ctx, cancelFunc := context.WithCancel(gw.ctx)

	monitor := &GlobalCertificateMonitor{
		gw:         gw,
		store:      store,
		ctx:        ctx,
		cancelFunc: cancelFunc,
		logger:     logger,
	}

	// Initialize server certificate batcher
	apiData := certcheck.APIMetaData{
		APIID:   "", // Empty for system-level events
		APIName: "",
	}

	cfg := gw.GetConfig().Security.CertificateExpiryMonitor

	serverBatcher, err := certcheck.NewCertificateExpiryCheckBatcherWithType(
		logger,
		apiData,
		cfg,
		store,
		monitor.fireSystemEvent,
		"server",
	)
	if err != nil {
		logger.WithError(err).Error("Failed to create server certificate batcher")
		cancelFunc()
		return nil, err
	}
	monitor.serverCertBatcher = serverBatcher

	// Initialize CA certificate batcher
	caBatcher, err := certcheck.NewCertificateExpiryCheckBatcherWithType(
		logger,
		apiData,
		cfg,
		store,
		monitor.fireSystemEvent,
		"ca",
	)
	if err != nil {
		logger.WithError(err).Error("Failed to create CA certificate batcher")
		cancelFunc()
		return nil, err
	}
	monitor.caCertBatcher = caBatcher

	return monitor, nil
}

// fireSystemEvent wraps Gateway.FireSystemEvent to match the FireEventFunc signature
func (m *GlobalCertificateMonitor) fireSystemEvent(name apidef.TykEvent, meta interface{}) {
	m.gw.FireSystemEvent(name, meta)
}

// Start begins background monitoring
func (m *GlobalCertificateMonitor) Start() {
	m.logger.Info("Starting global certificate expiry monitoring")

	// Start background batchers
	go m.serverCertBatcher.RunInBackground(m.ctx)
	go m.caCertBatcher.RunInBackground(m.ctx)
}

// Stop gracefully shuts down the monitor
func (m *GlobalCertificateMonitor) Stop() {
	m.logger.Info("Stopping global certificate expiry monitoring")

	if m.cancelFunc != nil {
		m.cancelFunc()
	}
}

// CheckServerCertificates checks the expiry status of server certificates
func (m *GlobalCertificateMonitor) CheckServerCertificates(certificates []tls.Certificate) {
	if m.serverCertBatcher == nil {
		return
	}

	checked := 0
	for i := range certificates {
		if certInfo, ok := m.extractCertInfo(&certificates[i], "server"); ok {
			m.serverCertBatcher.Add(certInfo)
			checked++
		}
	}

	if checked > 0 {
		m.logger.WithField("count", checked).Debug("Checked server certificates for expiry")
	}
}

// CheckServerCertificatesPtr checks the expiry status of server certificates (pointer slice variant)
func (m *GlobalCertificateMonitor) CheckServerCertificatesPtr(certificates []*tls.Certificate) {
	if m.serverCertBatcher == nil {
		return
	}

	checked := 0
	for _, cert := range certificates {
		if certInfo, ok := m.extractCertInfo(cert, "server"); ok {
			m.serverCertBatcher.Add(certInfo)
			checked++
		}
	}

	if checked > 0 {
		m.logger.WithField("count", checked).Debug("Checked server certificates for expiry")
	}
}

// CheckCACertificates checks the expiry status of CA certificates
func (m *GlobalCertificateMonitor) CheckCACertificates(certificates []*tls.Certificate) {
	if m.caCertBatcher == nil {
		return
	}

	checked := 0
	for _, cert := range certificates {
		if certInfo, ok := m.extractCertInfo(cert, "ca"); ok {
			m.caCertBatcher.Add(certInfo)
			checked++
		}
	}

	if checked > 0 {
		m.logger.WithField("count", checked).Debug("Checked CA certificates for expiry")
	}
}

// extractCertInfo validates the certificate and extracts basic information
func (m *GlobalCertificateMonitor) extractCertInfo(cert *tls.Certificate, certType string) (certInfo certcheck.CertInfo, ok bool) {
	if cert == nil || cert.Leaf == nil {
		m.logger.
			WithField("cert_type", certType).
			Warning("Extract Cert Info: Skipping invalid certificate")
		return certcheck.CertInfo{}, false
	}

	certID := crypto.HexSHA256(cert.Leaf.Raw)
	if certID == "" {
		m.logger.
			WithField("cert_type", certType).
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
