package gateway

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"io"
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

func (m *ResponseCacheMiddleware) CreateCheckSum(req *http.Request, keyName string, regex string, additionalKeyFromHeaders string) (string, error) {
	h := md5.New()

	// Compose key into string
	key := req.Method + "-" + req.URL.String()
	if additionalKeyFromHeaders != "" {
		key = key + "-" + additionalKeyFromHeaders
	}

	_, err := io.WriteString(h, key)
	if err != nil {
		return "", err
	}

	if e := addBodyHash(req, regex, h); e != nil {
		return "", e
	}

	reqChecksum := hex.EncodeToString(h.Sum(nil))
	return m.spec.APIID + keyName + reqChecksum, nil
}

func (m *ResponseCacheMiddleware) getTimeTTL(cacheTTL int64) string {
	timeNow := time.Now().Unix()
	newTTL := timeNow + cacheTTL
	asStr := strconv.Itoa(int(newTTL))
	return asStr
}

func (m *ResponseCacheMiddleware) encodePayload(payload, timestamp string) string {
	sEnc := base64.StdEncoding.EncodeToString([]byte(payload))
	return sEnc + "|" + timestamp
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
		m.Logger().Debug("Redis cache is disabled")
		return nil
	}

	// Has cache been enabled on the request?
	key, ok := ctxGetUseCacheKey(r)
	if !ok {
		m.Logger().Debug("Request is not cacheable")
		return nil
	}

	m.Logger().Debugf("YES, we can cache request to %s", key)

	var cacheMeta *EndPointCacheMeta

	cacheThisRequest := true
	cacheTTL := m.spec.CacheOptions.CacheTimeout

	cacheOnlyResponseCodes := m.spec.CacheOptions.CacheOnlyResponseCodes
	// override api main CacheOnlyResponseCodes by endpoint specific if provided
	if cacheMeta != nil && len(cacheMeta.CacheOnlyResponseCodes) > 0 {
		cacheOnlyResponseCodes = cacheMeta.CacheOnlyResponseCodes
	}

	// make sure the status codes match if specified
	if len(cacheOnlyResponseCodes) > 0 {
		foundCode := false
		for _, code := range cacheOnlyResponseCodes {
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

	if cacheThisRequest {
		var wireFormatReq bytes.Buffer
		if _, err = res.Write(&wireFormatReq); err != nil {
			m.Logger().WithError(err).Error("error encoding cache")
			return nil
		}

		ts := m.getTimeTTL(cacheTTL)
		toStore := m.encodePayload(wireFormatReq.String(), ts)

		go func() {
			err := m.store.SetKey(key, toStore, cacheTTL)
			if err != nil {
				m.Logger().WithError(err).Error("could not save key in cache store")
			}
		}()
	}

	m.Logger().WithField("cached_request", cacheThisRequest).Debug("Done cache")
	return nil
}
