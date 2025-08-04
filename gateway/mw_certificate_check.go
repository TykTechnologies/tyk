package gateway

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/internal/event"
)

// CertificateCheckMW is used if domain was not detected or multiple APIs bind on the same domain. In this case authentification check happens not on TLS side but on HTTP level using this middleware
type CertificateCheckMW struct {
	*BaseMiddleware
	certIDCache sync.Map // Cache for certificate IDs to avoid repeated hashing
}

func (m *CertificateCheckMW) Name() string {
	return "CertificateCheckMW"
}

func (m *CertificateCheckMW) EnabledForSpec() bool {
	return m.Spec.UseMutualTLSAuth
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
			log.Warning("Certificate validation failed: ", err)
			return err, http.StatusForbidden
		}

		// Log certificate check initiation
		log.Debug("Starting certificate expiration check for API: ", m.Spec.APIID, " with ", len(apiCerts), " certificates")

		m.checkCertificateExpiration(apiCerts)
	}

	return nil, http.StatusOK
}

// checkCertificateExpiration checks if certificates are expiring soon and fires events
func (m *CertificateCheckMW) checkCertificateExpiration(certs []*tls.Certificate) {
	// Safety check for tests where gateway might not be fully initialized
	if m.Gw == nil {
		log.Warning("Certificate expiry monitor: Gateway not initialized, skipping certificate checks")
		return
	}

	config := m.Gw.GetConfig().Security.CertificateExpiryMonitor
	now := time.Now()

	log.Debug("Certificate expiry monitor: Starting check for ", len(certs), " certificates with warning threshold of ", config.WarningThresholdDays, " days")

	// Use a worker pool to process certificates in parallel
	// Limit concurrency to avoid overwhelming the system
	maxConcurrent := config.MaxConcurrentChecks

	// Calculate optimal worker count
	var maxWorkers int
	if len(certs) <= 2 {
		maxWorkers = 1
	} else if maxConcurrent == 0 {
		maxWorkers = len(certs)
	} else if maxConcurrent < 0 {
		maxWorkers = 1
	} else if len(certs) <= maxConcurrent {
		maxWorkers = len(certs)
	} else {
		maxWorkers = maxConcurrent
	}

	// Create a channel to send certificates to workers
	certChan := make(chan *tls.Certificate, len(certs))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cert := range certChan {
				m.checkCertificate(cert, config, now)
			}
		}()
	}

	// Send certificates to workers
	for _, cert := range certs {
		certChan <- cert
	}

	close(certChan)

	// Wait for all workers to complete
	wg.Wait()
}

// checkCertificate checks a single certificate for expiration and fires appropriate events
// based on the certificate's expiry status and configured cooldown periods.
func (m *CertificateCheckMW) checkCertificate(cert *tls.Certificate, config config.CertificateExpiryMonitorConfig, now time.Time) {
	// Validate certificate is not nil and has a valid Leaf (parsed certificate)
	if cert == nil || cert.Leaf == nil {
		log.Warning("Certificate expiry monitor: Skipping nil certificate or certificate with nil Leaf")
		return
	}

	// Generate unique certificate ID for tracking and cooldown management
	certID := m.generateCertificateID(cert)

	// Check if we should skip this certificate based on check cooldown
	// This prevents checking the same certificate too frequently
	if m.shouldSkipCertificate(certID, config) {
		log.Debugf("Certificate expiry monitor: Skipping check for certificate '%s' due to cooldown (ID: %s...)", cert.Leaf.Subject.CommonName, certID[:8])
		return
	}

	// Extract basic certificate information for logging and processing
	commonName := cert.Leaf.Subject.CommonName
	hoursUntilExpiry := int(cert.Leaf.NotAfter.Sub(now).Hours())

	// Log the certificate being checked for debugging purposes
	log.Debugf("Certificate expiry monitor: Checking certificate '%s' - Hours until expiry: %d", commonName, hoursUntilExpiry)

	// Determine certificate status and handle accordingly
	switch {
	case hoursUntilExpiry < 0:
		// Certificate has already expired (negative hours means past expiry date)
		log.Warningf("Certificate expiry monitor: CRITICAL - Certificate '%s' has EXPIRED (ID: %s...)", commonName, certID[:8])

		// Check if we should fire the expired event based on event cooldown
		// This prevents firing the same event repeatedly for the same certificate
		if m.shouldFireExpiryEvent(certID, config) {
			m.fireCertificateExpiredEvent(cert, certID)
			log.Infof("Certificate expiry monitor: EXPIRED EVENT FIRED for certificate '%s' (ID: %s...)", commonName, certID[:8])
		} else {
			log.Debugf("Certificate expiry monitor: Expired event suppressed for certificate '%s' due to cooldown (ID: %s...)", commonName, certID[:8])
		}

	case hoursUntilExpiry <= config.WarningThresholdDays*24:
		// Certificate is expiring soon (within the configured warning threshold)
		log.Infof("Certificate expiry monitor: Certificate '%s' is expiring soon (%d hours remaining) - checking event cooldown", commonName, hoursUntilExpiry)

		// Check if we should fire the expiring soon event based on event cooldown
		if m.shouldFireExpiryEvent(certID, config) {
			m.fireCertificateExpiringSoonEvent(cert, hoursUntilExpiry)
			log.Infof("Certificate expiry monitor: EXPIRY EVENT FIRED for certificate '%s' - expires in %d hours (ID: %s...)", commonName, hoursUntilExpiry, certID[:8])
		} else {
			log.Debugf("Certificate expiry monitor: Event suppressed for certificate '%s' due to cooldown (ID: %s...)", commonName, certID[:8])
		}

	default:
		// Certificate is healthy (expires beyond the warning threshold)
		log.Debugf("Certificate expiry monitor: Certificate '%s' is healthy - expires in %d hours (ID: %s...)", commonName, hoursUntilExpiry, certID[:8])
	}
}

// generateCertificateID generates a unique ID for the certificate with caching to avoid repeated hashing
func (m *CertificateCheckMW) generateCertificateID(cert *tls.Certificate) string {
	if cert == nil || cert.Leaf == nil || len(cert.Leaf.Raw) == 0 {
		return ""
	}

	// Create a cache key from the certificate's raw data
	cacheKey := string(cert.Leaf.Raw)

	// Check if we already have this certificate ID cached
	if cachedID, ok := m.certIDCache.Load(cacheKey); ok {
		return cachedID.(string)
	}

	// Generate new hash if not cached
	hash := sha256.Sum256(cert.Leaf.Raw)
	certID := hex.EncodeToString(hash[:])

	// Cache the result
	m.certIDCache.Store(cacheKey, certID)

	return certID
}

// shouldSkipCertificate checks if a certificate check should be skipped based on check cooldown
func (m *CertificateCheckMW) shouldSkipCertificate(certID string, config config.CertificateExpiryMonitorConfig) bool {
	if certID == "" {
		log.Warningf("Certificate expiry monitor: Cannot check cooldown - empty certificate ID")
		return true // Skip check if no certificate ID
	}

	// If check cooldown is 0, never skip checks
	if config.CheckCooldownSeconds <= 0 {
		log.Debugf("Certificate expiry monitor: Check cooldown disabled (0 seconds) - allowing check for certificate ID: %s...", certID[:8])
		return false
	}

	checkCooldownKey := fmt.Sprintf("cert_check_cooldown:%s", certID)

	_, exists := m.Gw.UtilCache.Get(checkCooldownKey)
	if exists {
		log.Debugf("Certificate expiry monitor: Check cooldown active for certificate ID: %s... (cooldown: %ds)", certID[:8], config.CheckCooldownSeconds)
		return true // Skip check due to cooldown
	}

	// Set check cooldown
	m.Gw.UtilCache.Set(checkCooldownKey, "1", int64(config.CheckCooldownSeconds))

	log.Debugf("Certificate expiry monitor: Check cooldown set for certificate ID: %s... (cooldown: %ds)", certID[:8], config.CheckCooldownSeconds)

	return false // Don't skip check
}

// shouldFireExpiryEvent checks if an event should be fired based on cooldown
func (m *CertificateCheckMW) shouldFireExpiryEvent(certID string, config config.CertificateExpiryMonitorConfig) bool {
	if certID == "" {
		log.Warningf("Certificate expiry monitor: Cannot check event cooldown - empty certificate ID")
		return false
	}

	// If event cooldown is 0, always allow events
	if config.EventCooldownSeconds <= 0 {
		log.Debugf("Certificate expiry monitor: Event cooldown disabled (0 seconds) - allowing event for certificate ID: %s...", certID[:8])
		return true
	}

	cooldownKey := fmt.Sprintf("cert_expiry_cooldown:%s", certID)

	_, exists := m.Gw.UtilCache.Get(cooldownKey)
	if exists {
		log.Debugf("Certificate expiry monitor: Event cooldown active for certificate ID: %s... (cooldown: %ds)", certID[:8], config.EventCooldownSeconds)
		return false
	}

	// Set cooldown
	m.Gw.UtilCache.Set(cooldownKey, "1", int64(config.EventCooldownSeconds))

	log.Debugf("Certificate expiry monitor: Event cooldown set for certificate ID: %s... (cooldown: %ds)", certID[:8], config.EventCooldownSeconds)

	return true
}

// fireCertificateExpiringSoonEvent fires the certificate expiring soon event
func (m *CertificateCheckMW) fireCertificateExpiringSoonEvent(cert *tls.Certificate, hoursUntilExpiry int) {
	if cert == nil || cert.Leaf == nil {
		log.Warningf("Certificate expiry monitor: Cannot fire event - nil certificate or certificate with nil Leaf")
		return
	}

	certID := m.generateCertificateID(cert)

	// Convert hours to days and remaining hours for display
	daysUntilExpiry := hoursUntilExpiry / 24
	remainingHours := hoursUntilExpiry % 24

	var message string

	if daysUntilExpiry > 0 {
		if remainingHours > 0 {
			message = fmt.Sprintf("Certificate %s is expiring in %d days and %d hours", cert.Leaf.Subject.CommonName, daysUntilExpiry, remainingHours)
		} else {
			message = fmt.Sprintf("Certificate %s is expiring in %d days", cert.Leaf.Subject.CommonName, daysUntilExpiry)
		}
	} else {
		message = fmt.Sprintf("Certificate %s is expiring in %d hours", cert.Leaf.Subject.CommonName, remainingHours)
	}

	eventMeta := EventCertificateExpiringSoonMeta{
		EventMetaDefault: EventMetaDefault{
			Message: message,
		},
		CertificateID:   certID,
		CertificateName: cert.Leaf.Subject.CommonName,
		ExpirationDate:  cert.Leaf.NotAfter,
		DaysUntilExpiry: daysUntilExpiry,
		APIID:           m.Spec.APIID,
		OrgID:           m.Spec.OrgID,
	}

	log.Debugf("Certificate expiry monitor: Firing expiry event for certificate '%s' - expires in %dd %dh (ID: %s...)", cert.Leaf.Subject.CommonName, daysUntilExpiry, remainingHours, certID[:8])

	m.Spec.FireEvent(event.CertificateExpiringSoon, eventMeta)
}

// fireCertificateExpiredEvent fires an event when a certificate has expired
func (m *CertificateCheckMW) fireCertificateExpiredEvent(cert *tls.Certificate, certID string) {
	// TODO: Implement certificate expired event logic
}
