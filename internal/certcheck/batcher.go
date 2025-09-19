package certcheck

//go:generate mockgen -destination=./batcher_mock.go -package certcheck . Batcher,BackgroundBatcher

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/storage"
)

var (
	// ErrFallbackCooldownCheckFailed is returned when the fallback cache is used, and the check cooldown cannot be checked.
	ErrFallbackCooldownCheckFailed = errors.New("failed to check cooldown in fallback cache")
)

// Batch is a queue of certificates that are ready to be checked.
type Batch struct {
	lookupTable map[string]any
	batchQueue  []CertInfo
	mutex       sync.Mutex
}

// NewBatch creates a new Batch.
func NewBatch() *Batch {
	return &Batch{
		lookupTable: make(map[string]any),
		batchQueue:  make([]CertInfo, 0),
		mutex:       sync.Mutex{},
	}
}

// Append adds a certificate to the batch.
func (b *Batch) Append(certInfo CertInfo) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	_, exists := b.lookupTable[certInfo.ID]
	if exists {
		return
	}

	b.lookupTable[certInfo.ID] = struct{}{}
	b.batchQueue = append(b.batchQueue, certInfo)
}

// Size returns the number of certificates in the batch.
func (b *Batch) Size() int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return len(b.batchQueue)
}

// CopyAndClear returns a copy of the batch and clears the batch.
func (b *Batch) CopyAndClear() []CertInfo {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	batchCopy := make([]CertInfo, len(b.batchQueue))
	copy(batchCopy, b.batchQueue)

	b.lookupTable = make(map[string]any)
	b.batchQueue = b.batchQueue[:0]

	return batchCopy
}

// Batcher processes and manages the addition of CertInfo objects, ensuring they are handled in a batch-like manner.
type Batcher interface {
	Add(cert CertInfo) error
}

// BackgroundBatcher is a Batcher that can be run in the background.
type BackgroundBatcher interface {
	Batcher
	RunInBackground(ctx context.Context)
	SetFlushInterval(time.Duration)
}

// CertificateExpiryCheckBatcher is a Batcher that checks certificates for expiry.
type CertificateExpiryCheckBatcher struct {
	logger                *logrus.Entry
	apiMetaData           APIMetaData
	config                config.CertificateExpiryMonitorConfig
	batch                 *Batch
	inMemoryCooldownCache CooldownCache
	fallbackCooldownCache CooldownCache
	flushTicker           *time.Ticker
	fireEvent             FireEventFunc
}

// NewCertificateExpiryCheckBatcher creates a new CertificateExpiryCheckBatcher.
func NewCertificateExpiryCheckBatcher(logger *logrus.Entry, apiMetaData APIMetaData, cfg config.CertificateExpiryMonitorConfig, fallbackStorage storage.Handler, eventFunc FireEventFunc) (*CertificateExpiryCheckBatcher, error) {
	inMemoryCache, err := NewInMemoryCooldownCache()
	if err != nil {
		return nil, err
	}

	fallbackCache, err := NewRedisCooldownCache(fallbackStorage)
	if err != nil {
		return nil, err
	}

	logger = logger.WithField("api_id", apiMetaData.APIID).
		WithField("api_name", apiMetaData.APIName).
		WithField("task", "CertificateExpiryMonitorTask")

	return &CertificateExpiryCheckBatcher{
		logger:                logger,
		apiMetaData:           apiMetaData,
		config:                cfg,
		batch:                 NewBatch(),
		inMemoryCooldownCache: inMemoryCache,
		fallbackCooldownCache: fallbackCache,
		flushTicker:           time.NewTicker(30 * time.Second),
		fireEvent:             eventFunc,
	}, nil
}

// Add adds a certificate to the batch.
func (c *CertificateExpiryCheckBatcher) Add(cert CertInfo) error {
	c.batch.Append(cert)
	return nil
}

// RunInBackground runs the batcher in the background.
func (c *CertificateExpiryCheckBatcher) RunInBackground(ctx context.Context) {
	for {
		c.logger.
			WithField("batch_size", c.batch.Size()).
			Debug("Flush certificate expiry monitor batch")

		batchCopy := c.batch.CopyAndClear()
		for _, certInfo := range batchCopy {
			existsInLocalCache := c.checkCooldownExistsInLocalCache(certInfo)
			checkCooldownIsActive, err := c.isCheckCooldownActive(certInfo, existsInLocalCache)
			if err != nil {
				c.logger.
					WithField("certID", certInfo.ID[:8]).
					WithField("cooldown", "check").
					WithError(err).
					Error("Failed to check cooldown - skipping certificate")
				continue
			}

			if checkCooldownIsActive {
				continue
			}

			isExpired := c.isCertificateExpired(certInfo)
			isExpiringSoon := c.isCertificateExpiringSoon(certInfo)
			if isExpired || isExpiringSoon {
				c.handleEventForCertificate(certInfo, isExpired)
			}

			c.setCheckCooldown(certInfo)
		}

		select {
		case <-ctx.Done():
			return
		case <-c.flushTicker.C:
			continue
		}
	}
}

// SetFlushInterval sets the interval at which the batcher will flush the batch.
func (c *CertificateExpiryCheckBatcher) SetFlushInterval(interval time.Duration) {
	c.flushTicker.Reset(interval)
}

func (c *CertificateExpiryCheckBatcher) checkCooldownExistsInLocalCache(certInfo CertInfo) (exists bool) {
	var err error
	exists, err = c.inMemoryCooldownCache.HasCheckCooldown(certInfo.ID)
	if err != nil {
		c.logger.WithError(err).
			WithField("certID", certInfo.ID[:8]).
			WithField("cooldown", "check").
			Error("Failed to check if check cooldown exists in in-memory cache")
	}
	return exists
}

func (c *CertificateExpiryCheckBatcher) isCheckCooldownActive(certInfo CertInfo, foundInLocalCache bool) (bool, error) {
	checkCooldownActive := false
	fallback := false
	if foundInLocalCache {
		var err error
		checkCooldownActive, err = c.inMemoryCooldownCache.IsCheckCooldownActive(certInfo.ID)
		if err != nil {
			fallback = true
			c.logger.
				WithError(err).
				WithField("certID", certInfo.ID[:8]).
				WithField("cooldown", "check").
				Error("Failed to check if check cooldown is active in in-memory cache")
		}
	}

	if !foundInLocalCache || fallback {
		var err error
		checkCooldownActive, err = c.fallbackCooldownCache.IsCheckCooldownActive(certInfo.ID)
		if err != nil {
			c.logger.
				WithError(err).
				WithField("certID", certInfo.ID[:8]).
				WithField("cooldown", "check").
				Error("Failed to check if check cooldown is active in fallback cache")
			return false, ErrFallbackCooldownCheckFailed
		}
	}

	return checkCooldownActive, nil
}

func (c *CertificateExpiryCheckBatcher) setCheckCooldown(certInfo CertInfo) {
	err := c.inMemoryCooldownCache.SetCheckCooldown(certInfo.ID, int64(c.config.CheckCooldownSeconds))
	if err != nil {
		c.logger.WithError(err).
			WithField("certID", certInfo.ID[:8]).
			WithField("cooldown", "check").
			Error("Failed to set check cooldown for certificate in in-memory cache")
	}
	err = c.fallbackCooldownCache.SetCheckCooldown(certInfo.ID, int64(c.config.CheckCooldownSeconds))
	if err != nil {
		c.logger.WithError(err).
			WithField("certID", certInfo.ID[:8]).
			WithField("cooldown", "check").
			Error("Failed to set check cooldown for certificate in fallback cache")
	}
}

func (c *CertificateExpiryCheckBatcher) isCertificateExpired(certInfo CertInfo) bool {
	return certInfo.TimeUntilExpiry < 0
}

func (c *CertificateExpiryCheckBatcher) isCertificateExpiringSoon(certInfo CertInfo) bool {
	warningThresholdDays := c.config.WarningThresholdDays

	if warningThresholdDays == 0 {
		warningThresholdDays = config.DefaultWarningThresholdDays
	}

	warningThresholdDuration := time.Duration(warningThresholdDays) * 24 * time.Hour

	return certInfo.TimeUntilExpiry >= 0 && certInfo.TimeUntilExpiry <= warningThresholdDuration
}

func (c *CertificateExpiryCheckBatcher) handleEventForCertificate(certInfo CertInfo, isExpired bool) {
	exists := c.fireEventCooldownExistsInLocalCache(certInfo)
	isFireEventCooldownActive, err := c.isFireEventCooldownActive(certInfo, exists)
	if err != nil {
		c.logger.
			WithField("certID", certInfo.ID[:8]).
			WithField("cooldown", "fireEvent").
			WithError(err).
			Error("Failed to check cooldown - skipping certificate")
		return
	}

	if isFireEventCooldownActive {
		return
	}

	if isExpired {
		c.handleEventForExpiredCertificate(certInfo)
	} else {
		c.handleEventForSoonToExpireCertificate(certInfo)
	}

	c.setFireEventCooldown(certInfo)
}

func (c *CertificateExpiryCheckBatcher) handleEventForExpiredCertificate(certInfo CertInfo) {
	totalHours := int(certInfo.TimeUntilExpiry.Hours())
	daysSinceExpiry := (totalHours / 24) * -1
	hoursSinceExpiry := (totalHours % -24) * -1

	eventMeta := EventCertificateExpiredMeta{
		EventMetaDefault: model.EventMetaDefault{
			Message: c.composeExpiredMessage(certInfo, daysSinceExpiry, hoursSinceExpiry),
		},
		CertID:          certInfo.ID,
		CertName:        certInfo.CommonName,
		ExpiredAt:       certInfo.NotAfter,
		DaysSinceExpiry: daysSinceExpiry,
		APIID:           c.apiMetaData.APIID,
	}

	c.fireEvent(event.CertificateExpired, eventMeta)
	c.logger.
		WithField("cert_id", certInfo.ID[:8]).
		WithField("event_type", string(event.CertificateExpired)).
		Debugf("EXPIRY EVENT FIRED for certificate '%s' - expired since %d hours", certInfo.CommonName, int(certInfo.TimeUntilExpiry.Hours()))
}

func (c *CertificateExpiryCheckBatcher) handleEventForSoonToExpireCertificate(certInfo CertInfo) {
	totalHours := int(certInfo.TimeUntilExpiry.Hours())
	daysUntilExpiry := totalHours / 24
	remainingHours := totalHours % 24

	eventMeta := EventCertificateExpiringSoonMeta{
		EventMetaDefault: model.EventMetaDefault{
			Message: c.composeSoonToExpireMessage(certInfo, daysUntilExpiry, remainingHours),
		},
		CertID:        certInfo.ID,
		CertName:      certInfo.CommonName,
		ExpiresAt:     certInfo.NotAfter,
		DaysRemaining: daysUntilExpiry,
		APIID:         c.apiMetaData.APIID,
	}

	c.fireEvent(event.CertificateExpiringSoon, eventMeta)
	c.logger.
		WithField("cert_id", certInfo.ID[:8]).
		WithField("event_type", string(event.CertificateExpiringSoon)).
		Debugf("EXPIRY EVENT FIRED for certificate '%s' - expires in %d hours", certInfo.CommonName, int(certInfo.TimeUntilExpiry.Hours()))
}

func (c *CertificateExpiryCheckBatcher) fireEventCooldownExistsInLocalCache(certInfo CertInfo) (exists bool) {
	var err error
	exists, err = c.inMemoryCooldownCache.HasFireEventCooldown(certInfo.ID)
	if err != nil {
		c.logger.WithError(err).
			WithField("certID", certInfo.ID[:8]).
			WithField("cooldown", "fireEvent").
			Error("failed to check if fire event cooldown exists in in-memory cache")
	}
	return exists
}

func (c *CertificateExpiryCheckBatcher) isFireEventCooldownActive(certInfo CertInfo, foundInLocalCache bool) (bool, error) {
	fireEventCooldownActive := false
	useFallback := false

	if foundInLocalCache {
		var err error
		fireEventCooldownActive, err = c.inMemoryCooldownCache.IsFireEventCooldownActive(certInfo.ID)
		if err != nil {
			c.logger.
				WithError(err).
				WithField("certID", certInfo.ID[:8]).
				WithField("cooldown", "fireEvent").
				Error("Failed to check if fire event cooldown is active in in-memory cache")
			useFallback = true
		}
	}

	if !foundInLocalCache || useFallback {
		var err error
		fireEventCooldownActive, err = c.fallbackCooldownCache.IsFireEventCooldownActive(certInfo.ID)
		if err != nil {
			c.logger.
				WithError(err).
				WithField("certID", certInfo.ID[:8]).
				WithField("cooldown", "fireEvent").
				Error("Failed to check if fire event cooldown is active in fallback cache")

			return false, ErrFallbackCooldownCheckFailed
		}
	}
	return fireEventCooldownActive, nil
}

func (c *CertificateExpiryCheckBatcher) setFireEventCooldown(certInfo CertInfo) {
	err := c.inMemoryCooldownCache.SetFireEventCooldown(certInfo.ID, int64(c.config.EventCooldownSeconds))
	if err != nil {
		c.logger.WithError(err).
			WithField("certID", certInfo.ID[:8]).
			WithField("cooldown", "fireEvent").
			Error("Failed to set fire event cooldown for certificate in in-memory cache")
	}
	err = c.fallbackCooldownCache.SetFireEventCooldown(certInfo.ID, int64(c.config.EventCooldownSeconds))
	if err != nil {
		c.logger.WithError(err).
			WithField("certID", certInfo.ID[:8]).
			WithField("cooldown", "fireEvent").
			Error("Failed to set fire event cooldown for certificate in fallback cache")
	}
}

func (c *CertificateExpiryCheckBatcher) composeSoonToExpireMessage(certInfo CertInfo, daysUntilExpiry int, remainingHours int) string {
	if daysUntilExpiry > 0 {
		if remainingHours > 0 {
			return fmt.Sprintf("Certificate %s is expiring in %d days and %d hours", certInfo.CommonName, daysUntilExpiry, remainingHours)
		} else {
			return fmt.Sprintf("Certificate %s is expiring in %d days", certInfo.CommonName, daysUntilExpiry)
		}
	}
	return fmt.Sprintf("Certificate %s is expiring in %d hours", certInfo.CommonName, remainingHours)
}

func (c *CertificateExpiryCheckBatcher) composeExpiredMessage(certInfo CertInfo, daysSinceExpiry int, hoursSinceExpiry int) string {
	if daysSinceExpiry > 0 {
		if hoursSinceExpiry > 0 {
			return fmt.Sprintf("Certificate %s is expired since %d days and %d hours", certInfo.CommonName, daysSinceExpiry, hoursSinceExpiry)
		} else {
			return fmt.Sprintf("Certificate %s is expired since %d days", certInfo.CommonName, daysSinceExpiry)
		}
	}
	return fmt.Sprintf("Certificate %s is expired since %d hours", certInfo.CommonName, hoursSinceExpiry)
}

// Interface Guards
var _ BackgroundBatcher = (*CertificateExpiryCheckBatcher)(nil)
