package gateway

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

const (
	upstreamCacheHeader    = "x-tyk-cache-action-set"
	upstreamCacheTTLHeader = "x-tyk-cache-action-set-ttl"
)

// ResponseCacheMiddleware is a caching middleware that will pull data from Redis instead of the upstream proxy
type ResponseCacheMiddleware struct {
	spec  *APISpec
	store storage.Handler
}

func (m *ResponseCacheMiddleware) Name() string {
	return "ResponseCacheMiddleware"
}

func (h *ResponseCacheMiddleware) Init(c interface{}, spec *APISpec) error {
	h.spec = spec
	return nil
}

func (h *ResponseCacheMiddleware) HandleError(rw http.ResponseWriter, req *http.Request) {
}

func (m *ResponseCacheMiddleware) EnabledForSpec() bool {
	return m.spec.CacheOptions.EnableCache
}

func (m *ResponseCacheMiddleware) getTimeTTL(cacheTTL int64) int64 {
	timeNow := time.Now().Unix()
	return timeNow + cacheTTL
}

func (m *ResponseCacheMiddleware) encodePayload(payload string, timestamp int64) string {
	sEnc := base64.StdEncoding.EncodeToString([]byte(payload))
	return sEnc + "|" + fmt.Sprint(timestamp)
}

func (m *ResponseCacheMiddleware) Logger() *logrus.Entry {
	return log.WithField("mw", m.Name())
}

// HandleResponse checks if the http.Response argument can be cached and caches it for future requests.
func (m *ResponseCacheMiddleware) HandleResponse(w http.ResponseWriter, res *http.Response, r *http.Request, ses *user.SessionState) error {
	// No cache of empty responses
	if res == nil {
		m.Logger().Warning("Upstream request must have failed, response is empty")
		return nil
	}

	// Skip caching the request if cache disabled
	if !m.EnabledForSpec() {
		return nil
	}

	// Has cache been enabled on the request?
	options := ctxGetCacheOptions(r)
	if options == nil {
		m.Logger().Debug("Request is not cacheable")
		return nil
	}

	cacheThisRequest := true
	cacheTTL := m.spec.CacheOptions.CacheTimeout

	// make sure the status codes match if specified
	if len(options.cacheOnlyResponseCodes) > 0 {
		foundCode := false
		for _, code := range options.cacheOnlyResponseCodes {
			if code == res.StatusCode {
				foundCode = true
				break
			}
		}
		cacheThisRequest = foundCode
	}

	// Are we using upstream cache control?
	if m.spec.CacheOptions.EnableUpstreamCacheControl {
		// Do we enable cache for this response?
		if res.Header.Get(upstreamCacheHeader) != "" {
			cacheThisRequest = true
		}

		// Read custom or default cache TTL header name
		cacheTTLHeader := upstreamCacheTTLHeader
		if m.spec.CacheOptions.CacheControlTTLHeader != "" {
			cacheTTLHeader = m.spec.CacheOptions.CacheControlTTLHeader
		}

		// Get cache TTL from header
		ttl := res.Header.Get(cacheTTLHeader)
		if ttl != "" {
			if cacheAsInt, err := strconv.Atoi(ttl); err == nil {
				cacheTTL = int64(cacheAsInt)
			}
		}
	}

	var toStore string
	var err error

	if cacheThisRequest {
		res.Body, err = newNopCloserBuffer(res.Body)
		if err != nil {
			m.Logger().WithError(err).Error("error reading cache body")
			return nil
		}

		var wireFormatReq bytes.Buffer
		if err := res.Write(&wireFormatReq); err != nil {
			m.Logger().WithError(err).Error("error encoding cache")
			return nil
		}

		ts := m.getTimeTTL(cacheTTL)
		toStore = m.encodePayload(wireFormatReq.String(), ts)

		go func() {
			err := m.store.SetKey(options.key, toStore, cacheTTL)
			if err != nil {
				m.Logger().WithError(err).Error("could not save key in cache store")
			}
		}()
	}

	/*
		m.Logger().
			WithError(err).
			WithField("cache", cacheThisRequest).
			WithField("stored", toStore).
			WithField("key", options.key).
			Debug("Done response cache")
	*/

	return nil
}
