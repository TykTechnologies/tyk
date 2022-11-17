package gateway

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/request"
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
	io.WriteString(h, req.Method)
	io.WriteString(h, "-"+req.URL.String())
	if additionalKeyFromHeaders != "" {
		io.WriteString(h, "-"+additionalKeyFromHeaders)
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

func (m *ResponseCacheMiddleware) isTimeStampExpired(timestamp string) bool {
	now := time.Now()

	i, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		log.Error(err)
	}
	tm := time.Unix(i, 0)

	log.Debug("Time Now: ", now)
	log.Debug("Expires: ", tm)
	if tm.Before(now) {
		log.Debug("Expriy caught in TS!")
		return true
	}

	return false
}

func (m *ResponseCacheMiddleware) encodePayload(payload, timestamp string) string {
	sEnc := base64.StdEncoding.EncodeToString([]byte(payload))
	return sEnc + "|" + timestamp
}

func (m *ResponseCacheMiddleware) decodePayload(payload string) (string, string, error) {
	data := strings.Split(payload, "|")
	switch len(data) {
	case 1:
		return data[0], "", nil
	case 2:
		sDec, err := base64.StdEncoding.DecodeString(data[0])
		if err != nil {
			return "", "", err
		}

		return string(sDec), data[1], nil
	}
	return "", "", errors.New("Decoding failed, array length wrong")
}

// HandleResponse checks if the http.Response argument can be cached and caches it for future requests.
func (m *ResponseCacheMiddleware) HandleResponse(w http.ResponseWriter, res *http.Response, r *http.Request, ses *user.SessionState) error {
	// No cache of empty responses
	if res == nil {
		log.Warning("Upstream request must have failed, response is empty")
		return nil
	}

	// Skip caching the request if cache disabled
	if !m.EnabledForSpec() {
		return nil
	}

	var stat RequestStatus
	var cacheKeyRegex string
	var cacheMeta *EndPointCacheMeta

	version, _ := m.spec.Version(r)
	versionPaths := m.spec.RxPaths[version.Name]

	// Lets see if we can throw a sledgehammer at this
	if m.spec.CacheOptions.CacheAllSafeRequests && isSafeMethod(r.Method) {
		stat = StatusCached
	}
	if stat != StatusCached {
		// New request checker, more targeted, less likely to fail
		found, meta := m.spec.CheckSpecMatchesStatus(r, versionPaths, Cached)
		if found {
			cacheMeta = meta.(*EndPointCacheMeta)
			stat = StatusCached
			cacheKeyRegex = cacheMeta.CacheKeyRegex
		}
	}

	// Cached route matched, let go
	if stat != StatusCached {
		return nil
	}

	token := ctxGetAuthToken(r)

	// No authentication data? use the IP.
	if token == "" {
		token = request.RealIP(r)
	}

	key, err := m.CreateCheckSum(r, token, cacheKeyRegex, m.getCacheKeyFromHeaders(r))
	if err != nil {
		log.WithError(err).Debug("Error creating checksum. Skipping cache write")
		return nil
	}

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
		res.Write(&wireFormatReq)
		ts := m.getTimeTTL(cacheTTL)
		toStore := m.encodePayload(wireFormatReq.String(), ts)

		go func() {
			err := m.store.SetKey(key, toStore, cacheTTL)
			if err != nil {
				log.WithError(err).Error("could not save key in cache store")
			}
		}()
	}

	return nil
}

func (m *ResponseCacheMiddleware) getCacheKeyFromHeaders(r *http.Request) (key string) {
	key = ""
	for _, header := range m.spec.CacheOptions.CacheByHeaders {
		key += header + "-" + r.Header.Get(header)
	}
	return
}
