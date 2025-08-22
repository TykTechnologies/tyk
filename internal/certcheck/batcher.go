package certcheck

//go:generate mockgen -destination=./mock/batcher.go -package mock . Batcher, BackgroundBatcher

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/storage"
)

type Batch struct {
	lookupTable map[string]any
	batchQueue  []CertInfo
	mutex       sync.Mutex
}

func NewBatch() *Batch {
	return &Batch{
		lookupTable: make(map[string]any),
		batchQueue:  make([]CertInfo, 0),
		mutex:       sync.Mutex{},
	}
}

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

func (b *Batch) Size() int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return len(b.batchQueue)
}

func (b *Batch) CopyAndClear() []CertInfo {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	batchCopy := make([]CertInfo, len(b.batchQueue))
	for i, certInfo := range b.batchQueue {
		batchCopy[i] = certInfo
	}

	b.lookupTable = make(map[string]any)
	b.batchQueue = b.batchQueue[:0]

	return batchCopy
}

type Batcher interface {
	Add(cert CertInfo) error
}

type BackgroundBatcher interface {
	Batcher
	RunInBackground(ctx context.Context)
}

type CertificateExpiryCheckBatcher struct {
	logger             *logrus.Entry
	config             config.CertificateExpiryMonitorConfig
	batch              *Batch
	localCooldownCache CooldownCache
	redisCooldownCache CooldownCache
	flushTicker        *time.Ticker
	fireEvent          FireEventFunc
}

func NewCertificateExpiryCheckBatcher(logger *logrus.Entry, cfg config.CertificateExpiryMonitorConfig, redisStorage storage.Handler, eventFunc FireEventFunc) (*CertificateExpiryCheckBatcher, error) {
	localCache, err := NewLocalCooldownCache(128)
	if err != nil {
		return nil, err
	}

	redisCache, err := NewRedisCooldownCache(redisStorage)
	if err != nil {
		return nil, err
	}

	return &CertificateExpiryCheckBatcher{
		logger:             logger,
		config:             cfg,
		batch:              NewBatch(),
		localCooldownCache: localCache,
		redisCooldownCache: redisCache,
		flushTicker:        time.NewTicker(30 * time.Second),
		fireEvent:          eventFunc,
	}, nil
}

func (c *CertificateExpiryCheckBatcher) Add(cert CertInfo) error {
	c.batch.Append(cert)
	return nil
}

func (c *CertificateExpiryCheckBatcher) RunInBackground(ctx context.Context) {
	for {
		batchCopy := c.batch.CopyAndClear()
		for _, certInfo := range batchCopy {
			exists, redisFallback := c.checkCooldownExistsInLocalCache(certInfo)
			checkCooldownIsActive := c.isCheckCooldownActive(certInfo, exists, redisFallback)
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

func (c *CertificateExpiryCheckBatcher) checkCooldownExistsInLocalCache(certInfo CertInfo) (exists bool, fallbackToRedis bool) {
	var err error
	exists, err = c.localCooldownCache.HasCheckCooldown(certInfo.ID)
	if err != nil {
		c.logger.WithError(err).
			WithField("certID", certInfo.ID[:8]).
			Error("failed to check if check cooldown exists in local cache")

		fallbackToRedis = true
	}
	return exists, fallbackToRedis
}

func (c *CertificateExpiryCheckBatcher) isCheckCooldownActive(certInfo CertInfo, foundInLocalCache bool, fallbackToRedis bool) bool {
	checkCooldownActive := false
	if foundInLocalCache && !fallbackToRedis {
		var err error
		checkCooldownActive, err = c.localCooldownCache.IsCheckCooldownActive(certInfo.ID)
		if err != nil {
			c.logger.
				WithError(err).
				WithField("certID", certInfo.ID[:8]).
				Error("failed to check if check cooldown is active in local cache")
		}
	} else {
		var err error
		checkCooldownActive, err = c.redisCooldownCache.IsCheckCooldownActive(certInfo.ID)
		if err != nil {
			c.logger.
				WithError(err).
				WithField("certID", certInfo.ID[:8]).
				Error("failed to check if check cooldown is active in redis")
		}
	}
	return checkCooldownActive
}

func (c *CertificateExpiryCheckBatcher) setCheckCooldown(certInfo CertInfo) {
	err := c.localCooldownCache.SetCheckCooldown(certInfo.ID, int64(c.config.CheckCooldownSeconds))
	if err != nil {
		c.logger.WithError(err).
			WithField("certID", certInfo.ID[:8]).
			Error("failed to set check cooldown for certificate in local cache")
	}
	err = c.redisCooldownCache.SetCheckCooldown(certInfo.ID, int64(c.config.CheckCooldownSeconds))
	if err != nil {
		c.logger.WithError(err).
			WithField("certID", certInfo.ID[:8]).
			Error("failed to set check cooldown for certificate in redis")
	}
}

func (c *CertificateExpiryCheckBatcher) isCertificateExpired(certInfo CertInfo) bool {
	return certInfo.HoursUntilExpiry < 0
}

func (c *CertificateExpiryCheckBatcher) isCertificateExpiringSoon(certInfo CertInfo) bool {
	warningThresholdDays := c.config.WarningThresholdDays

	if warningThresholdDays == 0 {
		warningThresholdDays = config.DefaultWarningThresholdDays
	}

	warningThresholdHours := warningThresholdDays * 24

	return certInfo.HoursUntilExpiry >= 0 && certInfo.HoursUntilExpiry <= warningThresholdHours
}

func (c *CertificateExpiryCheckBatcher) handleEventForCertificate(certInfo CertInfo, isExpired bool) {
	exists, redisFallback := c.fireEventCooldownExistsInLocalCache(certInfo)
	isFireEventCooldownActive := c.isFireEventCooldownActive(certInfo, exists, redisFallback)
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
	// Implementation will happen in another ticket
}

func (c *CertificateExpiryCheckBatcher) handleEventForSoonToExpireCertificate(certInfo CertInfo) {
	if certInfo.Certificate == nil || certInfo.Certificate.Leaf == nil {
		c.logger.Warningf("Certificate expiry monitor: Cannot fire event - nil certificate or certificate with nil Leaf")
		return
	}

	// Convert hours to days and remaining hours for display
	daysUntilExpiry := certInfo.HoursUntilExpiry / 24
	remainingHours := certInfo.HoursUntilExpiry % 24

	var message string

	if daysUntilExpiry > 0 {
		if remainingHours > 0 {
			message = fmt.Sprintf("Certificate %s is expiring in %d days and %d hours", certInfo.Certificate.Leaf.Subject.CommonName, daysUntilExpiry, remainingHours)
		} else {
			message = fmt.Sprintf("Certificate %s is expiring in %d days", certInfo.Certificate.Leaf.Subject.CommonName, daysUntilExpiry)
		}
	} else {
		message = fmt.Sprintf("Certificate %s is expiring in %d hours", certInfo.Certificate.Leaf.Subject.CommonName, remainingHours)
	}

	eventMeta := EventCertificateExpiringSoonMeta{
		EventMetaDefault: model.EventMetaDefault{
			Message: message,
		},
		CertID:        certInfo.ID,
		CertName:      certInfo.Certificate.Leaf.Subject.CommonName,
		ExpiresAt:     certInfo.Certificate.Leaf.NotAfter,
		DaysRemaining: daysUntilExpiry,
	}

	c.fireEvent(event.CertificateExpiringSoon, eventMeta)
	c.logger.Debugf("Certificate expiry monitor: EXPIRY EVENT FIRED for certificate '%s' - expires in %d hours (ID: %s...)", certInfo.CommonName, certInfo.HoursUntilExpiry, certInfo.ID[:8])
}

func (c *CertificateExpiryCheckBatcher) fireEventCooldownExistsInLocalCache(certInfo CertInfo) (exists bool, fallbackToRedis bool) {
	var err error
	exists, err = c.localCooldownCache.HasFireEventCooldown(certInfo.ID)
	if err != nil {
		c.logger.WithError(err).
			WithField("certID", certInfo.ID[:8]).
			Error("failed to check if fire event cooldown exists in local cache")

		fallbackToRedis = true
	}
	return exists, fallbackToRedis
}

func (c *CertificateExpiryCheckBatcher) isFireEventCooldownActive(certInfo CertInfo, foundInLocalCache bool, fallbackToRedis bool) bool {
	fireEventCooldownActive := false
	if foundInLocalCache && !fallbackToRedis {
		var err error
		fireEventCooldownActive, err = c.localCooldownCache.IsFireEventCooldownActive(certInfo.ID)
		if err != nil {
			c.logger.
				WithError(err).
				WithField("certID", certInfo.ID[:8]).
				Error("failed to check if fire event cooldown is active in local cache")
		}
	} else {
		var err error
		fireEventCooldownActive, err = c.redisCooldownCache.IsFireEventCooldownActive(certInfo.ID)
		if err != nil {
			c.logger.
				WithError(err).
				WithField("certID", certInfo.ID[:8]).
				Error("failed to check if fire event cooldown is active in redis")
		}
	}
	return fireEventCooldownActive
}

func (c *CertificateExpiryCheckBatcher) setFireEventCooldown(certInfo CertInfo) {
	err := c.localCooldownCache.SetFireEventCooldown(certInfo.ID, int64(c.config.EventCooldownSeconds))
	if err != nil {
		c.logger.WithError(err).
			WithField("certID", certInfo.ID[:8]).
			Error("failed to set fire event cooldown for certificate in local cache")
	}
	err = c.redisCooldownCache.SetFireEventCooldown(certInfo.ID, int64(c.config.EventCooldownSeconds))
	if err != nil {
		c.logger.WithError(err).
			WithField("certID", certInfo.ID[:8]).
			Error("failed to set fire event cooldown for certificate in redis")
	}
}

// Interface Guards
var _ BackgroundBatcher = (*CertificateExpiryCheckBatcher)(nil)
