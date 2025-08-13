package gateway

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/storage"
)

const (
	// Certificate check cooldown key prefix for Redis
	certCheckCooldownPrefix = "cert_check_cooldown:"
	// Certificate expiry event cooldown key prefix for Redis
	certExpiryCooldownPrefix = "cert_expiry_cooldown:"
)

// CertificateCheckMW is used if domain was not detected or multiple APIs bind on the same domain. In this case authentification check happens not on TLS side but on HTTP level using this middleware
type CertificateCheckMW struct {
	*BaseMiddleware
	store storage.Handler // Redis storage for cooldowns
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
			log.Warning("[CertificateCheckMW] Certificate validation failed: ", err)

			return err, http.StatusForbidden
		}

		// Log certificate check initiation
		log.Debug("Starting certificate expiration check for API: ", m.Spec.APIID, " with ", len(apiCerts), " certificates")

		// Initialize Redis store for cooldowns if not already done
		if m.store == nil {
			log.Debug("[CertificateCheckMW] Initializing Redis store for cooldowns.")

			m.store = &storage.RedisCluster{
				KeyPrefix:         "cert-cooldown:",
				ConnectionHandler: m.Gw.StorageConnectionHandler,
			}

			m.store.Connect()
		}

		// NOTE: Certificate expiration checking is currently performed synchronously, which may block the request.
		// Consider making this asynchronous in the future to improve request response times, especially when
		// processing large numbers of certificates or when Redis operations are slow.
		m.checkCertificatesExpiration(apiCerts)
	}

	return nil, http.StatusOK
}

// checkCertificatesExpiration checks if certificates are expiring soon and fires events
func (m *CertificateCheckMW) checkCertificatesExpiration(certificates []*tls.Certificate) {
	if m.Gw == nil {
		log.Warning("Certificate expiry monitor: Gateway not initialized, skipping certificate checks")
		return
	}

	monitorConfig := m.Gw.GetConfig().Security.CertificateExpiryMonitor
	now := time.Now()

	log.Debug("[CertificateCheckMW] Starting expiration check for ", len(certificates), " certificates with warning threshold of ", monitorConfig.WarningThresholdDays, " days")

	// NOTE: In the future, consider using a worker pool pattern instead of spawning a goroutine per certificate.
	// This would help limit resource usage with large numbers of certificates by:
	// 1. Using a fixed number of worker goroutines
	// 2. Processing certificates through a buffered channel
	// 3. Providing better backpressure handling
	// 4. Allowing for more controlled error handling and retries
	var wg sync.WaitGroup

	for i, cert := range certificates {
		if cert == nil {
			continue
		}

		wg.Add(1)

		go func(cert *tls.Certificate, idx int) {
			defer wg.Done()
			log.Debugf("[CertificateCheckMW] Checking certificate %d/%d", idx+1, len(certificates))
			m.checkCertificate(cert, monitorConfig, now)
		}(cert, i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
}

// checkCertificate checks a single certificate for expiration and fires appropriate events
// based on the certificate's expiry status and configured cooldown periods.
func (m *CertificateCheckMW) checkCertificate(cert *tls.Certificate, monitorConfig config.CertificateExpiryMonitorConfig, _ time.Time) {
	// Validate certificate and get certificate info
	certInfo := m.extractCertInfo(cert)
	if certInfo == nil {
		return
	}

	// Check if we should skip this certificate based on check cooldown
	if m.shouldCooldown(monitorConfig, certInfo.ID) {
		log.Debugf("Certificate expiry monitor: Skipping check for certificate '%s' due to cooldown (ID: %s...)", certInfo.CommonName, certInfo.ID[:8])

		return
	}

	// Log the certificate being checked for debugging purposes
	log.Debugf("Certificate expiry monitor: Checking certificate '%s' - Hours until expiry: %d", certInfo.CommonName, certInfo.HoursUntilExpiry)

	// Process certificate based on its expiry status
	switch {
	case certInfo.IsExpired:
		m.handleExpiredCertificate(certInfo, monitorConfig)
	case certInfo.IsExpiringSoon:
		m.handleExpiringSoonCertificate(certInfo, monitorConfig)
	default:
		m.handleHealthyCertificate(certInfo)
	}
}

// certInfo holds certificate information for processing
type certInfo struct {
	Certificate      *tls.Certificate
	ID               string
	CommonName       string
	HoursUntilExpiry int
	IsExpired        bool
	IsExpiringSoon   bool
}

// extractCertInfo validates the certificate and extracts basic information
func (m *CertificateCheckMW) extractCertInfo(cert *tls.Certificate) *certInfo {
	if cert == nil || cert.Leaf == nil {
		log.Warning("Certificate expiry monitor: Skipping nil certificate or certificate with nil Leaf")
		return nil
	}

	certID := crypto.HexSHA256(cert.Leaf.Raw)
	if certID == "" {
		log.Warning("Certificate expiry monitor: Skipping certificate with empty ID (no raw data)")
		return nil
	}

	commonName := cert.Leaf.Subject.CommonName
	hoursUntilExpiry := int(time.Until(cert.Leaf.NotAfter).Hours())

	return &certInfo{
		Certificate:      cert,
		ID:               certID,
		CommonName:       commonName,
		HoursUntilExpiry: hoursUntilExpiry,
		IsExpired:        hoursUntilExpiry < 0,
		IsExpiringSoon:   m.isCertificateExpiringSoon(hoursUntilExpiry),
	}
}

// isCertificateExpiringSoon checks if a certificate is expiring within the configured warning threshold
func (m *CertificateCheckMW) isCertificateExpiringSoon(hoursUntilExpiry int) bool {
	// NOTE: Configuration is retrieved fresh on each call, which allows hot reload to take effect.
	// However, existing cooldowns in Redis are not invalidated when configuration changes.
	// This means that if WarningThresholdDays is updated via hot reload, certificates with active
	// cooldowns will continue to use the old threshold until their cooldown expires.
	// Consider implementing cooldown invalidation when configuration changes to ensure consistent behavior.
	warningThresholdDays := m.Gw.GetConfig().Security.CertificateExpiryMonitor.WarningThresholdDays

	if warningThresholdDays == 0 {
		warningThresholdDays = config.DefaultWarningThresholdDays
	}

	warningThresholdHours := warningThresholdDays * 24

	return hoursUntilExpiry >= 0 && hoursUntilExpiry <= warningThresholdHours
}

// handleExpiredCertificate handles certificates that have already expired
func (m *CertificateCheckMW) handleExpiredCertificate(certInfo *certInfo, monitorConfig config.CertificateExpiryMonitorConfig) {
	log.Warningf("Certificate expiry monitor: CRITICAL - Certificate '%s' has EXPIRED (ID: %s...)", certInfo.CommonName, certInfo.ID[:8])

	// Check if we should fire the expired event based on cooldown
	if !m.shouldFireExpiryEvent(certInfo.ID, monitorConfig) {
		log.Debugf("Certificate expiry monitor: Event suppressed for expired certificate '%s' due to cooldown (ID: %s...)", certInfo.CommonName, certInfo.ID[:8])
		return
	}

	// Fire CertificateExpired event
	m.fireCertificateExpiredEvent(certInfo.Certificate, certInfo.ID)

	log.Infof("Certificate expiry monitor: EXPIRED EVENT FIRED for certificate '%s' - expired %d days ago (ID: %s...)", certInfo.CommonName, int(time.Since(certInfo.Certificate.Leaf.NotAfter).Hours()/24), certInfo.ID[:8])
}

// handleExpiringSoonCertificate handles certificates that are expiring soon
func (m *CertificateCheckMW) handleExpiringSoonCertificate(certInfo *certInfo, monitorConfig config.CertificateExpiryMonitorConfig) {
	log.Infof("Certificate expiry monitor: Certificate '%s' is expiring soon (%d hours remaining) - checking event cooldown", certInfo.CommonName, certInfo.HoursUntilExpiry)

	if !m.shouldFireExpiryEvent(certInfo.ID, monitorConfig) {
		log.Debugf("Certificate expiry monitor: Event suppressed for certificate '%s' due to cooldown (ID: %s...)", certInfo.CommonName, certInfo.ID[:8])
		return
	}

	m.fireCertificateExpiringSoonEvent(certInfo.Certificate, certInfo.ID, certInfo.HoursUntilExpiry)

	log.Infof("Certificate expiry monitor: EXPIRY EVENT FIRED for certificate '%s' - expires in %d hours (ID: %s...)", certInfo.CommonName, certInfo.HoursUntilExpiry, certInfo.ID[:8])
}

// handleHealthyCertificate handles certificates that are healthy
func (m *CertificateCheckMW) handleHealthyCertificate(certInfo *certInfo) {
	log.Debugf("Certificate expiry monitor: Certificate '%s' is healthy - expires in %d hours (ID: %s...)", certInfo.CommonName, certInfo.HoursUntilExpiry, certInfo.ID[:8])
}

// shouldCooldown checks if a certificate check should be skipped based on check cooldown
func (m *CertificateCheckMW) shouldCooldown(monitorConfig config.CertificateExpiryMonitorConfig, certID string) bool {
	// NOTE: This method currently has a race condition where multiple goroutines checking the same certificate
	// could both proceed with their operations. The current storage.Handler interface doesn't provide atomic
	// operations, so we use a check-then-set pattern. In the future, consider extending the Handler interface
	// to support atomic operations (e.g., SET key value NX EX seconds) to eliminate the race condition and
	// improve performance. This would replace the current check-then-set pattern with a single atomic operation.

	checkCooldownSeconds := monitorConfig.CheckCooldownSeconds

	if checkCooldownSeconds == 0 {
		checkCooldownSeconds = config.DefaultCheckCooldownSeconds
	}

	checkCooldownKey := fmt.Sprintf("%s%s", certCheckCooldownPrefix, certID)

	// Use Redis for cooldowns
	if m.store == nil {
		// Store not initialized, skip cooldown check
		return false
	}

	_, err := m.store.GetKey(checkCooldownKey)
	if err == nil {
		log.Debugf("Certificate expiry monitor: Check cooldown active for certificate ID: %s... (cooldown: %ds)", certID[:8], checkCooldownSeconds)
		return true // Skip check due to cooldown
	}
	// Set check cooldown atomically (protected by lock)
	if err := m.store.SetKey(checkCooldownKey, "1", int64(checkCooldownSeconds)); err != nil {
		log.Warningf("Certificate expiry monitor: Failed to set check cooldown for certificate ID: %s... - %v", certID[:8], err)
	}

	log.Debugf("Certificate expiry monitor: Check cooldown set for certificate ID: %s... (cooldown: %ds)", certID[:8], checkCooldownSeconds)

	return false
}

// shouldFireExpiryEvent checks if an event should be fired based on cooldown
func (m *CertificateCheckMW) shouldFireExpiryEvent(certID string, monitorConfig config.CertificateExpiryMonitorConfig) bool {
	// NOTE: This method currently has a race condition where multiple goroutines could both fire events
	// for the same certificate. In the future, consider using Redis atomic operations
	// (e.g., SET key value NX EX seconds) to eliminate the race condition and prevent duplicate events.
	// This would replace the current check-then-set pattern with a single atomic operation.

	eventCooldownSeconds := monitorConfig.EventCooldownSeconds

	if eventCooldownSeconds == 0 {
		eventCooldownSeconds = config.DefaultEventCooldownSeconds
	}

	// Use Redis for cooldowns
	if m.store == nil {
		// Store not initialized, allow event to fire
		return true
	}

	cooldownKey := fmt.Sprintf("%s%s", certExpiryCooldownPrefix, certID)

	_, err := m.store.GetKey(cooldownKey)
	if err == nil {
		log.Debugf("Certificate expiry monitor: Event cooldown active for certificate ID: %s... (cooldown: %ds)", certID[:8], eventCooldownSeconds)
		return false
	}

	// Set cooldown atomically (protected by lock)
	if err := m.store.SetKey(cooldownKey, "1", int64(eventCooldownSeconds)); err != nil {
		log.Warningf("Certificate expiry monitor: Failed to set event cooldown for certificate ID: %s... - %v", certID[:8], err)
	}

	log.Debugf("Certificate expiry monitor: Event cooldown set for certificate ID: %s... (cooldown: %ds)", certID[:8], eventCooldownSeconds)

	return true
}

// fireCertificateExpiringSoonEvent fires the certificate expiring soon event
func (m *CertificateCheckMW) fireCertificateExpiringSoonEvent(cert *tls.Certificate, certID string, hoursUntilExpiry int) {
	if cert == nil || cert.Leaf == nil {
		log.Warningf("Certificate expiry monitor: Cannot fire event - nil certificate or certificate with nil Leaf")
		return
	}

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
		CertID:        certID,
		CertName:      cert.Leaf.Subject.CommonName,
		ExpiresAt:     cert.Leaf.NotAfter,
		DaysRemaining: daysUntilExpiry,
		APIID:         m.Spec.APIID,
		OrgID:         m.Spec.OrgID,
	}

	log.Debugf("Certificate expiry monitor: Firing expiry event for certificate '%s' - expires in %dd %dh (ID: %s...)", cert.Leaf.Subject.CommonName, daysUntilExpiry, remainingHours, certID[:8])

	m.Spec.FireEvent(event.CertificateExpiringSoon, eventMeta)
}

// fireCertificateExpiredEvent fires the certificate expired event
func (m *CertificateCheckMW) fireCertificateExpiredEvent(cert *tls.Certificate, certID string) {
	if cert == nil || cert.Leaf == nil {
		log.Warningf("Certificate expiry monitor: Cannot fire expired event - nil certificate or certificate with nil Leaf")
		return
	}

	// Calculate days since expiration
	daysSinceExpiry := int(time.Since(cert.Leaf.NotAfter).Hours() / 24)
	if daysSinceExpiry < 0 {
		daysSinceExpiry = 0 // Should not happen for expired certificates, but safety check
	}

	message := fmt.Sprintf("Certificate %s has expired %d days ago", cert.Leaf.Subject.CommonName, daysSinceExpiry)

	eventMeta := EventCertificateExpiredMeta{
		EventMetaDefault: EventMetaDefault{
			Message: message,
		},
		CertID:     certID,
		CertName:   cert.Leaf.Subject.CommonName,
		ExpiresAt:  cert.Leaf.NotAfter,
		ExpiredFor: daysSinceExpiry,
		APIID:      m.Spec.APIID,
		OrgID:      m.Spec.OrgID,
	}

	log.Debugf("Certificate expiry monitor: Firing expired event for certificate '%s' - expired %d days ago (ID: %s...)", cert.Leaf.Subject.CommonName, daysSinceExpiry, certID[:8])

	m.Spec.FireEvent(event.CertificateExpired, eventMeta)
}
