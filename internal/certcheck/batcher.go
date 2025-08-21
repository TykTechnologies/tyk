package certcheck

import (
	"context"
	"sync"
	"time"
)

type Batcher interface {
	Add(cert CertInfo) error
}

type BackgroundBatcher interface {
	Batcher
	RunInBackground(ctx context.Context) error
}

type CertificateExpiryCheckBatcher struct {
	batchedCerts       map[string]CertInfo
	mutex              sync.Mutex
	localCooldownCache CooldownCache
	redisCooldownCache CooldownCache
	flushTicker        *time.Ticker
}

func NewCertificateExpiryCheckBatcher(flushInterval time.Duration) (*CertificateExpiryCheckBatcher, error) {
	return &CertificateExpiryCheckBatcher{
		batchedCerts: make(map[string]CertInfo),
		mutex:        sync.Mutex{},
		flushTicker:  time.NewTicker(flushInterval),
	}, nil
}

func (c *CertificateExpiryCheckBatcher) Add(cert CertInfo) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.batchedCerts[cert.ID] = cert
	return nil
}

func (c *CertificateExpiryCheckBatcher) RunInBackground(ctx context.Context) error {
	for range c.flushTicker.C {
		//batchCopy := c.copyAndClearBatch()
	}
	return nil
}

func (c *CertificateExpiryCheckBatcher) copyAndClearBatch() map[string]CertInfo {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	batchCopy := make(map[string]CertInfo, len(c.batchedCerts))
	for id, cert := range c.batchedCerts {
		batchCopy[id] = cert
	}

	c.batchedCerts = make(map[string]CertInfo)
	return batchCopy
}

// Interface Guards
var _ BackgroundBatcher = (*CertificateExpiryCheckBatcher)(nil)
