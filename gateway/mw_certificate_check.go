package gateway

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/storage"
)

// CertificateCheckMW is used if domain was not detected or multiple APIs bind on the same domain. In this case authentification check happens not on TLS side but on HTTP level using this middleware
type CertificateCheckMW struct {
	*BaseMiddleware
	certIDCache sync.Map        // Cache for certificate IDs to avoid repeated hashing
	certLocks   sync.Map        // Map of mutexes per certificate ID for thread-safe cooldown operations
	store       storage.Handler // Redis storage for cooldowns
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

		// Initialize Redis store for cooldowns if not already done
		if m.store == nil {
			m.store = &storage.RedisCluster{
				KeyPrefix:         "cert-cooldown:",
				ConnectionHandler: m.Gw.StorageConnectionHandler,
			}

			m.store.Connect()
		}

		// NOTE: Consider running certificate checks in the background to avoid blocking requests.
		// This would require:
		// 1. A background worker pool to process checks asynchronously
		// 2. A mechanism to track and limit concurrent background checks
		// 3. Error handling for background task failures
		// 4. Careful consideration of race conditions and state management
		// Currently this is a blocking call and will block the request until complete
		m.checkCertificateExpiration(apiCerts)
	}

	return nil, http.StatusOK
}

// checkCertificateExpiration checks if certificates are expiring soon and fires events
func (m *CertificateCheckMW) checkCertificateExpiration(certificates []*tls.Certificate) {
	// Safety check for tests where gateway might not be fully initialized
	if m.Gw == nil {
		log.Warning("Certificate expiry monitor: Gateway not initialized, skipping certificate checks")
		return
	}

	monitorConfig := m.Gw.GetConfig().Security.CertificateExpiryMonitor
	now := time.Now()

	log.Debug("Certificate expiry monitor: Starting check for ", len(certificates), " certificates with warning threshold of ", monitorConfig.WarningThresholdDays, " days")

	// Use a worker pool to process certificates in parallel
	// Calculate optimal worker count based on the following rules:
	// - For 2 or fewer certificates, use a single worker since parallelization overhead isn't worth it
	// - For 3-10 certificates, use 3 workers for good balance of parallelism and overhead
	// - For more than 10 certificates, use number of CPU cores to prevent system overload
	var maxWorkers int
	if len(certificates) <= 2 {
		maxWorkers = 1
	} else if len(certificates) <= 10 {
		maxWorkers = 3
	} else {
		maxWorkers = runtime.NumCPU()
	}

	// Create a channel to send certificates to workers
	certChan := make(chan *tls.Certificate, len(certificates))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cert := range certChan {
				m.checkCertificate(cert, monitorConfig, now)
			}
		}()
	}

	// Send certificates to workers
	for _, cert := range certificates {
		certChan <- cert
	}

	close(certChan)

	// Wait for all workers to complete
	wg.Wait()
}

// checkCertificate checks a single certificate for expiration and fires appropriate events
// based on the certificate's expiry status and configured cooldown periods.
func (m *CertificateCheckMW) checkCertificate(cert *tls.Certificate, monitorConfig config.CertificateExpiryMonitorConfig, now time.Time) {
	// Validate certificate and get certificate info
	certInfo := m.validateAndExtractCertInfo(cert)
	if certInfo == nil {
		return
	}

	// Check if we should skip this certificate based on check cooldown
	if m.shouldSkipCertificate(certInfo.ID, monitorConfig) {
		m.logSkipDueToCooldown(certInfo)
		return
	}

	// Log the certificate being checked for debugging purposes
	m.logCertificateCheck(certInfo)

	// Process certificate based on its expiry status
	m.processCertificateByStatus(certInfo, monitorConfig)
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

// validateAndExtractCertInfo validates the certificate and extracts basic information
func (m *CertificateCheckMW) validateAndExtractCertInfo(cert *tls.Certificate) *certInfo {
	if cert == nil || cert.Leaf == nil {
		log.Warning("Certificate expiry monitor: Skipping nil certificate or certificate with nil Leaf")
		return nil
	}

	certID := m.generateCertificateID(cert)
	commonName := cert.Leaf.Subject.CommonName
	hoursUntilExpiry := int(cert.Leaf.NotAfter.Sub(time.Now()).Hours())

	return &certInfo{
		Certificate:      cert,
		ID:               certID,
		CommonName:       commonName,
		HoursUntilExpiry: hoursUntilExpiry,
		IsExpired:        hoursUntilExpiry < 0,
		IsExpiringSoon:   hoursUntilExpiry >= 0 && hoursUntilExpiry <= m.Gw.GetConfig().Security.CertificateExpiryMonitor.WarningThresholdDays*24,
	}
}

// logSkipDueToCooldown logs when a certificate check is skipped due to cooldown
func (m *CertificateCheckMW) logSkipDueToCooldown(certInfo *certInfo) {
	if certInfo.ID != "" {
		log.Debugf("Certificate expiry monitor: Skipping check for certificate '%s' due to cooldown (ID: %s...)", certInfo.CommonName, certInfo.ID[:8])
	} else {
		log.Debugf("Certificate expiry monitor: Skipping check for certificate '%s' due to cooldown (ID: empty)", certInfo.CommonName)
	}
}

// logCertificateCheck logs the certificate being checked
func (m *CertificateCheckMW) logCertificateCheck(certInfo *certInfo) {
	log.Debugf("Certificate expiry monitor: Checking certificate '%s' - Hours until expiry: %d", certInfo.CommonName, certInfo.HoursUntilExpiry)
}

// processCertificateByStatus processes the certificate based on its expiry status
func (m *CertificateCheckMW) processCertificateByStatus(certInfo *certInfo, monitorConfig config.CertificateExpiryMonitorConfig) {
	switch {
	case certInfo.IsExpired:
		m.handleExpiredCertificate(certInfo)
	case certInfo.IsExpiringSoon:
		m.handleExpiringSoonCertificate(certInfo, monitorConfig)
	default:
		m.handleHealthyCertificate(certInfo)
	}
}

// handleExpiredCertificate handles certificates that have already expired
func (m *CertificateCheckMW) handleExpiredCertificate(certInfo *certInfo) {
	if certInfo.ID != "" {
		log.Warningf("Certificate expiry monitor: CRITICAL - Certificate '%s' has EXPIRED (ID: %s...)", certInfo.CommonName, certInfo.ID[:8])
	} else {
		log.Warningf("Certificate expiry monitor: CRITICAL - Certificate '%s' has EXPIRED (ID: empty)", certInfo.CommonName)
	}
}

// handleExpiringSoonCertificate handles certificates that are expiring soon
func (m *CertificateCheckMW) handleExpiringSoonCertificate(certInfo *certInfo, monitorConfig config.CertificateExpiryMonitorConfig) {
	log.Infof("Certificate expiry monitor: Certificate '%s' is expiring soon (%d hours remaining) - checking event cooldown", certInfo.CommonName, certInfo.HoursUntilExpiry)

	if m.shouldFireExpiryEvent(certInfo.ID, monitorConfig) {
		m.fireCertificateExpiringSoonEvent(certInfo.Certificate, certInfo.HoursUntilExpiry)
		m.logExpiryEventFired(certInfo)
	} else {
		m.logExpiryEventSuppressed(certInfo)
	}
}

// handleHealthyCertificate handles certificates that are healthy
func (m *CertificateCheckMW) handleHealthyCertificate(certInfo *certInfo) {
	if certInfo.ID != "" {
		log.Debugf("Certificate expiry monitor: Certificate '%s' is healthy - expires in %d hours (ID: %s...)", certInfo.CommonName, certInfo.HoursUntilExpiry, certInfo.ID[:8])
	} else {
		log.Debugf("Certificate expiry monitor: Certificate '%s' is healthy - expires in %d hours (ID: empty)", certInfo.CommonName, certInfo.HoursUntilExpiry)
	}
}

// logExpiryEventFired logs when an expiry event is fired
func (m *CertificateCheckMW) logExpiryEventFired(certInfo *certInfo) {
	if certInfo.ID != "" {
		log.Infof("Certificate expiry monitor: EXPIRY EVENT FIRED for certificate '%s' - expires in %d hours (ID: %s...)", certInfo.CommonName, certInfo.HoursUntilExpiry, certInfo.ID[:8])
	} else {
		log.Infof("Certificate expiry monitor: EXPIRY EVENT FIRED for certificate '%s' - expires in %d hours (ID: empty)", certInfo.CommonName, certInfo.HoursUntilExpiry)
	}
}

// logExpiryEventSuppressed logs when an expiry event is suppressed due to cooldown
func (m *CertificateCheckMW) logExpiryEventSuppressed(certInfo *certInfo) {
	if certInfo.ID != "" {
		log.Debugf("Certificate expiry monitor: Event suppressed for certificate '%s' due to cooldown (ID: %s...)", certInfo.CommonName, certInfo.ID[:8])
	} else {
		log.Debugf("Certificate expiry monitor: Event suppressed for certificate '%s' due to cooldown (ID: empty)", certInfo.CommonName)
	}
}

// generateCertificateID generates a unique ID for the certificate with caching to avoid repeated hashing
func (m *CertificateCheckMW) generateCertificateID(cert *tls.Certificate) string {
	if cert == nil || cert.Leaf == nil || len(cert.Leaf.Raw) == 0 {
		return ""
	}

	// Use SHA-256 hash of the raw bytes as the cache key to ensure uniqueness and avoid encoding issues
	hash := sha256.Sum256(cert.Leaf.Raw)
	cacheKey := hex.EncodeToString(hash[:])

	// Check if we already have this certificate ID cached
	if cachedID, ok := m.certIDCache.Load(cacheKey); ok {
		if cachedString, ok := cachedID.(string); ok {
			return cachedString
		}
		// If type assertion fails, fall through to regenerate
	}

	// Use the hash as the certificate ID (it's already unique)
	certID := cacheKey

	// Cache the result
	m.certIDCache.Store(cacheKey, certID)

	return certID
}

// acquireLock returns a mutex for the given certificate ID to ensure thread-safe operations
// This prevents race conditions when multiple goroutines check the same certificate simultaneously
func (m *CertificateCheckMW) acquireLock(certID string) *sync.Mutex {
	if certID == "" {
		return nil
	}

	// Get or create a mutex for this certificate ID
	lock, _ := m.certLocks.LoadOrStore(certID, &sync.Mutex{})
	if mutex, ok := lock.(*sync.Mutex); ok {
		return mutex
	}
	// If type assertion fails, return nil as fallback
	return nil
}

// shouldSkipCertificate checks if a certificate check should be skipped based on check cooldown
func (m *CertificateCheckMW) shouldSkipCertificate(certID string, monitorConfig config.CertificateExpiryMonitorConfig) bool {
	if certID == "" {
		log.Warningf("Certificate expiry monitor: Cannot check cooldown - empty certificate ID")
		return true // Skip check if no certificate ID
	}

	// Get certificate-specific lock to prevent race conditions
	lock := m.acquireLock(certID)
	if lock == nil {
		if certID != "" {
			log.Warningf("Certificate expiry monitor: Cannot get lock for certificate ID: %s", certID[:8])
		} else {
			log.Warningf("Certificate expiry monitor: Cannot get lock for certificate ID: empty")
		}
		return true // Skip check if we can't get a lock
	}

	lock.Lock()
	defer lock.Unlock()

	// If check cooldown is 0, never skip checks
	if monitorConfig.CheckCooldownSeconds <= 0 {
		log.Debugf("Certificate expiry monitor: Check cooldown disabled (0 seconds) - allowing check for certificate ID: %s...", certID[:8])
		return false
	}

	checkCooldownKey := fmt.Sprintf("cert_check_cooldown:%s", certID)

	// Use Redis for cooldowns
	if m.store == nil {
		// Store not initialized, skip cooldown check
		return false
	}
	_, err := m.store.GetKey(checkCooldownKey)
	if err == nil {
		log.Debugf("Certificate expiry monitor: Check cooldown active for certificate ID: %s... (cooldown: %ds)", certID[:8], monitorConfig.CheckCooldownSeconds)
		return true // Skip check due to cooldown
	}
	// Set check cooldown atomically (protected by lock)
	if err := m.store.SetKey(checkCooldownKey, "1", int64(monitorConfig.CheckCooldownSeconds)); err != nil {
		log.Warningf("Certificate expiry monitor: Failed to set check cooldown for certificate ID: %s... - %v", certID[:8], err)
	}
	if certID != "" {
		log.Debugf("Certificate expiry monitor: Check cooldown set for certificate ID: %s... (cooldown: %ds)", certID[:8], monitorConfig.CheckCooldownSeconds)
	} else {
		log.Debugf("Certificate expiry monitor: Check cooldown set for certificate ID: empty (cooldown: %ds)", monitorConfig.CheckCooldownSeconds)
	}

	return false // Don't skip check
}

// shouldFireExpiryEvent checks if an event should be fired based on cooldown
func (m *CertificateCheckMW) shouldFireExpiryEvent(certID string, monitorConfig config.CertificateExpiryMonitorConfig) bool {
	if certID == "" {
		log.Warningf("Certificate expiry monitor: Cannot check event cooldown - empty certificate ID")
		return false
	}

	// Get certificate-specific lock to prevent race conditions
	lock := m.acquireLock(certID)
	if lock == nil {
		if certID != "" {
			log.Warningf("Certificate expiry monitor: Cannot get lock for certificate ID: %s", certID[:8])
		} else {
			log.Warningf("Certificate expiry monitor: Cannot get lock for certificate ID: empty")
		}
		return false // Don't fire event if we can't get a lock
	}

	lock.Lock()
	defer lock.Unlock()

	// If event cooldown is 0, always allow events
	if monitorConfig.EventCooldownSeconds <= 0 {
		log.Debugf("Certificate expiry monitor: Event cooldown disabled (0 seconds) - allowing event for certificate ID: %s...", certID[:8])
		return true
	}

	cooldownKey := fmt.Sprintf("cert_expiry_cooldown:%s", certID)

	// Use Redis for cooldowns
	if m.store == nil {
		// Store not initialized, allow event to fire
		return true
	}
	_, err := m.store.GetKey(cooldownKey)
	if err == nil {
		log.Debugf("Certificate expiry monitor: Event cooldown active for certificate ID: %s... (cooldown: %ds)", certID[:8], monitorConfig.EventCooldownSeconds)
		return false
	}
	// Set cooldown atomically (protected by lock)
	if err := m.store.SetKey(cooldownKey, "1", int64(monitorConfig.EventCooldownSeconds)); err != nil {
		log.Warningf("Certificate expiry monitor: Failed to set event cooldown for certificate ID: %s... - %v", certID[:8], err)
	}
	if certID != "" {
		log.Debugf("Certificate expiry monitor: Event cooldown set for certificate ID: %s... (cooldown: %ds)", certID[:8], monitorConfig.EventCooldownSeconds)
	} else {
		log.Debugf("Certificate expiry monitor: Event cooldown set for certificate ID: empty (cooldown: %ds)", monitorConfig.EventCooldownSeconds)
	}

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

	if certID != "" {
		log.Debugf("Certificate expiry monitor: Firing expiry event for certificate '%s' - expires in %dd %dh (ID: %s...)", cert.Leaf.Subject.CommonName, daysUntilExpiry, remainingHours, certID[:8])
	} else {
		log.Debugf("Certificate expiry monitor: Firing expiry event for certificate '%s' - expires in %dd %dh (ID: empty)", cert.Leaf.Subject.CommonName, daysUntilExpiry, remainingHours)
	}

	m.Spec.FireEvent(event.CertificateExpiringSoon, eventMeta)
}
