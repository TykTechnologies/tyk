package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/mcp/client"
	"github.com/TykTechnologies/tyk/storage"
)

const (
	// introspectionCachePrefix is the Redis key prefix for cached introspection results.
	introspectionCachePrefix = "mcp-introspect:"

	// introspectionLockPrefix is the Redis key prefix for distributed introspection locks.
	introspectionLockPrefix = "mcp-introspect-lock:"

	// introspectionCacheTTL is the default TTL for cached introspection results (5 minutes).
	introspectionCacheTTL = 300

	// introspectionLockTTL is how long the distributed lock is held (30 seconds).
	// This should be longer than the introspection timeout to prevent a second
	// gateway from starting introspection before the first one finishes.
	introspectionLockTTL = 30 * time.Second

	// introspectionLockPollInterval is how often a gateway polls for the cache
	// after failing to acquire the lock (another gateway is introspecting).
	introspectionLockPollInterval = 500 * time.Millisecond

	// introspectionLockPollTimeout is the max time to wait for another gateway
	// to finish introspecting and populate the cache.
	introspectionLockPollTimeout = 15 * time.Second
)

// getIntrospectionConfig returns the MCPIntrospection config from an APISpec,
// or nil if the spec is not an MCP API or has no introspection configured.
func getIntrospectionConfig(spec *APISpec) *oas.MCPIntrospection {
	if spec == nil {
		return nil
	}

	ext := spec.OAS.GetTykExtension()
	if ext == nil {
		return nil
	}

	return ext.Server.Introspection
}

// introspectionCacheKey returns the Redis key for a cached introspection result.
func introspectionCacheKey(apiID string) string {
	return apiID
}

// introspectionLockKey returns the Redis key for the distributed lock.
func introspectionLockKey(apiID string) string {
	return apiID
}

// getIntrospectionStore returns a RedisCluster for introspection cache data.
func (gw *Gateway) getIntrospectionStore() *storage.RedisCluster {
	return &storage.RedisCluster{
		KeyPrefix:         introspectionCachePrefix,
		ConnectionHandler: gw.StorageConnectionHandler,
	}
}

// getIntrospectionLockStore returns a RedisCluster for introspection distributed locks.
func (gw *Gateway) getIntrospectionLockStore() *storage.RedisCluster {
	return &storage.RedisCluster{
		KeyPrefix:         introspectionLockPrefix,
		ConnectionHandler: gw.StorageConnectionHandler,
	}
}

// cachedIntrospectionResult represents what we store in Redis.
type cachedIntrospectionResult struct {
	Capabilities *client.ServerCapabilities `json:"capabilities"`
	Partial      bool                       `json:"partial"`
	CachedAt     time.Time                  `json:"cachedAt"`
}

// getCachedIntrospection retrieves a cached introspection result from Redis.
// Returns nil if not found, on error, or if Redis is not available.
func (gw *Gateway) getCachedIntrospection(apiID string) *cachedIntrospectionResult {
	if gw.StorageConnectionHandler == nil {
		return nil
	}

	store := gw.getIntrospectionStore()
	val, err := store.GetKey(introspectionCacheKey(apiID))
	if err != nil {
		return nil
	}

	var cached cachedIntrospectionResult
	if err := json.Unmarshal([]byte(val), &cached); err != nil {
		return nil
	}

	return &cached
}

// setCachedIntrospection stores an introspection result in Redis with a TTL.
// Silently skips if Redis is not available.
func (gw *Gateway) setCachedIntrospection(apiID string, caps *client.ServerCapabilities, partial bool) {
	if gw.StorageConnectionHandler == nil {
		return
	}

	store := gw.getIntrospectionStore()

	cached := cachedIntrospectionResult{
		Capabilities: caps,
		Partial:      partial,
		CachedAt:     time.Now(),
	}

	data, err := json.Marshal(cached)
	if err != nil {
		log.WithField("apiID", apiID).WithError(err).Warn("failed to marshal introspection cache")
		return
	}

	if err := store.SetKey(introspectionCacheKey(apiID), string(data), introspectionCacheTTL); err != nil {
		log.WithField("apiID", apiID).WithError(err).Warn("failed to write introspection cache to Redis")
	}
}

// acquireIntrospectionLock attempts to acquire a distributed lock for introspecting
// a specific API. Returns true if the lock was acquired (caller should introspect),
// false if another gateway already holds the lock (caller should poll cache).
func (gw *Gateway) acquireIntrospectionLock(apiID string) bool {
	if gw.StorageConnectionHandler == nil {
		return true // No Redis = no coordination, just introspect.
	}

	store := gw.getIntrospectionLockStore()
	acquired, err := store.Lock(introspectionLockKey(apiID), introspectionLockTTL)
	if err != nil {
		// On error, allow introspection to proceed rather than blocking.
		return true
	}

	return acquired
}

// waitForCachedIntrospection polls Redis for a cached result that another gateway
// is currently producing. Returns the cached result if it appears within the timeout,
// or nil if the timeout is reached.
func (gw *Gateway) waitForCachedIntrospection(apiID string) *cachedIntrospectionResult {
	logger := log.WithField("apiID", apiID)
	logger.Debug("another gateway is introspecting, waiting for cached result")

	deadline := time.Now().Add(introspectionLockPollTimeout)
	for time.Now().Before(deadline) {
		if cached := gw.getCachedIntrospection(apiID); cached != nil {
			logger.Debug("got cached introspection result from peer gateway")
			return cached
		}
		time.Sleep(introspectionLockPollInterval)
	}

	logger.Warn("timed out waiting for peer introspection result, will introspect directly")
	return nil
}

// runIntrospection performs a single introspection cycle against the upstream MCP server.
// If no introspection config is present, sensible defaults are used (10s timeout).
// The result is cached in Redis for other gateway instances.
func (gw *Gateway) runIntrospection(spec *APISpec) (*client.IntrospectionResult, error) {
	ext := spec.OAS.GetTykExtension()
	if ext == nil {
		return nil, fmt.Errorf("no OAS extension for API %s", spec.APIID)
	}

	cfg := getIntrospectionConfig(spec)
	var timeoutStr string
	if cfg != nil {
		timeoutStr = cfg.GetTimeout()
	} else {
		timeoutStr = "10s"
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return nil, fmt.Errorf("parse timeout %q: %w", timeoutStr, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c := client.New()
	result, err := c.Introspect(ctx, ext.Upstream.URL)
	if err != nil {
		return nil, err
	}

	// Cache the result in Redis so other gateway instances can use it.
	gw.setCachedIntrospection(spec.APIID, result.Capabilities, result.Partial)

	return result, nil
}

// runIntrospectionWithCache attempts to load introspection results from Redis first.
// If no cache exists, it uses a distributed lock to ensure only one gateway instance
// introspects the upstream at a time (preventing thundering herd on simultaneous restarts).
//
// Flow:
//  1. Check Redis cache -> return if found
//  2. Try to acquire distributed lock
//  3. If lock acquired: introspect live, cache result, return
//  4. If lock not acquired (peer is introspecting): poll cache until result appears or timeout
//  5. If poll times out: introspect live as fallback
func (gw *Gateway) runIntrospectionWithCache(spec *APISpec) (*client.IntrospectionResult, error) {
	logger := log.WithField("apiID", spec.APIID)

	// Step 1: Check cache.
	if cached := gw.getCachedIntrospection(spec.APIID); cached != nil {
		logger.Infof("using cached introspection result from %s", cached.CachedAt.Format(time.RFC3339))
		return &client.IntrospectionResult{
			Capabilities: cached.Capabilities,
			Partial:      cached.Partial,
		}, nil
	}

	// Step 2: Try to acquire the distributed lock.
	if gw.acquireIntrospectionLock(spec.APIID) {
		// Step 3: We won the lock - introspect live.
		logger.Info("acquired introspection lock, introspecting upstream")
		return gw.runIntrospection(spec)
	}

	// Step 4: Another gateway holds the lock - wait for its result.
	if cached := gw.waitForCachedIntrospection(spec.APIID); cached != nil {
		return &client.IntrospectionResult{
			Capabilities: cached.Capabilities,
			Partial:      cached.Partial,
		}, nil
	}

	// Step 5: Timeout - introspect directly as fallback.
	logger.Warn("lock wait timed out, introspecting upstream directly")
	return gw.runIntrospection(spec)
}

// buildDiscoveredPrimitives converts discovered server capabilities into the
// MCPPrimitives map format used by APISpec. It respects the discovery flags
// in the introspection config to filter which primitive types are included.
func buildDiscoveredPrimitives(caps *client.ServerCapabilities, cfg *oas.MCPIntrospection) map[string]string {
	if caps == nil {
		return nil
	}

	primitives := make(map[string]string)

	if cfg.ShouldDiscoverTools() {
		for _, t := range caps.Tools {
			key := "tool:" + t.Name
			vem := mcp.ToolPrefix + t.Name
			primitives[key] = vem
		}
	}

	if cfg.ShouldDiscoverResources() {
		for _, r := range caps.Resources {
			key := "resource:" + r.URI
			vem := mcp.ResourcePrefix + r.URI
			primitives[key] = vem
		}
	}

	if cfg.ShouldDiscoverPrompts() {
		for _, p := range caps.Prompts {
			key := "prompt:" + p.Name
			vem := mcp.PromptPrefix + p.Name
			primitives[key] = vem
		}
	}

	return primitives
}

// handleIntrospect validates that the API exists and is an MCP API, then runs
// an on-demand introspection cycle and returns the discovered capabilities.
// On-demand introspection always goes live (bypasses cache) and updates the cache.
func (gw *Gateway) handleIntrospect(apiID string) (any, int) {
	spec := gw.getApiSpec(apiID)
	if spec == nil {
		return apiError("API not found"), http.StatusNotFound
	}

	if !spec.IsMCP() {
		return apiError("API is not an MCP API"), http.StatusBadRequest
	}

	start := time.Now()
	result, err := gw.runIntrospection(spec)
	if err != nil {
		return apiError(fmt.Sprintf("introspection failed: %s", err.Error())), http.StatusBadGateway
	}

	return map[string]any{
		"status":       "ok",
		"durationMs":   time.Since(start).Milliseconds(),
		"capabilities": result.Capabilities,
		"partial":      result.Partial,
		"errors":       result.Errors,
	}, http.StatusOK
}

// mcpIntrospectHandler is the HTTP handler for triggering an on-demand
// introspection of an MCP API's upstream server.
func (gw *Gateway) mcpIntrospectHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	obj, code := gw.handleIntrospect(apiID)
	doJSONWrite(w, code, obj)
}
