package portal

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	// ErrCacheExpired indicates that the cached data has exceeded its TTL
	ErrCacheExpired = errors.New("cache expired")
	// ErrCacheMiss indicates that no data was found in the cache
	ErrCacheMiss = errors.New("cache miss")
)

// cachedWebhooks represents a cached set of webhook credentials with expiry time
type cachedWebhooks struct {
	webhooks []WebhookCredential // The actual webhook data
	expiry   time.Time          // When this cache entry expires
}

// CacheManager is a singleton that manages multiple portal client caches.
// It provides a shared caching layer to prevent duplicate API calls across
// different parts of the application using the same portal credentials.
type CacheManager struct {
	mu     sync.RWMutex                // Protects access to the caches map
	caches map[string]*CachedClient    // Map of portal URL+secret to its cached client
	done   chan struct{}               // Channel to signal shutdown of background refresh
}

var (
	globalManager     *CacheManager    // Single global instance of cache manager
	globalManagerOnce sync.Once        // Ensures singleton initialization
)

// GetCacheManager returns the global cache manager instance.
// It lazily initializes the manager on first call and starts
// the background refresh loop.
func GetCacheManager() *CacheManager {
	globalManagerOnce.Do(func() {
		globalManager = &CacheManager{
			caches: make(map[string]*CachedClient),
			done:   make(chan struct{}),
		}
		// Start background refresh loop that periodically checks for expired caches
		go globalManager.refreshLoop()
	})
	return globalManager
}

// Stop gracefully shuts down the cache manager by stopping the refresh loop
func (m *CacheManager) Stop() {
	close(m.done)
}

// refreshLoop runs in the background and periodically checks all caches
// for expiration, triggering a refresh if needed. This ensures that
// frequently accessed data stays fresh without blocking client requests.
func (m *CacheManager) refreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.refreshAllCaches()
		case <-m.done:
			return
		}
	}
}

// refreshAllCaches iterates through all cached clients and triggers
// a refresh for any that have expired data
func (m *CacheManager) refreshAllCaches() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ctx := context.Background()
	for _, cache := range m.caches {
		cache.refreshIfExpired(ctx)
	}
}

// GetOrCreateCache returns an existing cached client or creates a new one
// if none exists for the given portal URL and secret combination.
// This ensures we don't create duplicate caches for the same portal.
func (m *CacheManager) GetOrCreateCache(portalURL, secret string, ttl time.Duration) *CachedClient {
	key := portalURL + ":" + secret

	m.mu.Lock()
	defer m.mu.Unlock()

	if cache, ok := m.caches[key]; ok {
		return cache
	}

	client := NewClient(portalURL, secret)
	cache := NewCachedClient(client, ttl)
	m.caches[key] = cache
	return cache
}

// CachedClient wraps a portal Client with a caching layer.
// It implements the Client interface while adding caching functionality.
type CachedClient struct {
	client Client           // The underlying portal client
	ttl    time.Duration   // How long cache entries are valid

	mu       sync.RWMutex    // Protects access to the webhooks cache
	webhooks *cachedWebhooks // Current cached webhook data
}

// NewCachedClient creates a new cached client with specified TTL
func NewCachedClient(client Client, ttl time.Duration) *CachedClient {
	return &CachedClient{
		client: client,
		ttl:    ttl,
	}
}

// ListWebhookCredentials returns webhook credentials from cache or fetches them
// if the cache has expired. It checks the cache under a read lock first and
// only refreshes the cache if it's expired.
func (c *CachedClient) ListWebhookCredentials(ctx context.Context) ([]WebhookCredential, error) {
	c.mu.RLock()
	cached := c.webhooks
	c.mu.RUnlock()

	if cached != nil && time.Now().Before(cached.expiry) {
		return cached.webhooks, nil
	}

	return c.refreshCache(ctx)
}

// refreshIfExpired checks if the cache has expired and refreshes it if needed.
// This method is called periodically by the cache manager to ensure data stays fresh.
func (c *CachedClient) refreshIfExpired(ctx context.Context) {
	c.mu.RLock()
	expired := c.webhooks == nil || time.Now().After(c.webhooks.expiry)
	c.mu.RUnlock()

	if expired {
		_, _ = c.refreshCache(ctx)
	}
}

// refreshCache updates the cache by fetching the latest webhook credentials.
// It first checks under a write lock if the cache is still expired to prevent
// unnecessary refreshes.
func (c *CachedClient) refreshCache(ctx context.Context) ([]WebhookCredential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check expiration under write lock
	if c.webhooks != nil && time.Now().Before(c.webhooks.expiry) {
		return c.webhooks.webhooks, nil
	}

	webhooks, err := c.client.ListWebhookCredentials(ctx)
	if err != nil {
		return nil, err
	}

	c.webhooks = &cachedWebhooks{
		webhooks: webhooks,
		expiry:   time.Now().Add(c.ttl),
	}

	return webhooks, nil
}
