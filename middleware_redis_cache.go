package main

import (
	"bufio"
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
)

const (
	upstreamCacheHeader    = "x-tyk-cache-action-set"
	upstreamCacheTTLHeader = "x-tyk-cache-action-set-ttl"
)

// RedisCacheMiddleware is a caching middleware that will pull data from Redis instead of the upstream proxy
type RedisCacheMiddleware struct {
	*TykMiddleware
	CacheStore StorageHandler
	sh         SuccessHandler
}

func (m *RedisCacheMiddleware) GetName() string {
	return "RedisCacheMiddleware"
}

type RedisCacheMiddlewareConfig struct {
}

// New lets you do any initialisations for the object can be done here
func (m *RedisCacheMiddleware) New() {
	m.sh = SuccessHandler{m.TykMiddleware}
}

func (m *RedisCacheMiddleware) IsEnabledForSpec() bool {
	var used bool
	for _, version := range m.TykMiddleware.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.Cached) > 0 {
			used = true
		}
	}

	return used
}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *RedisCacheMiddleware) GetConfig() (interface{}, error) {
	return RedisCacheMiddlewareConfig{}, nil
}

func (m *RedisCacheMiddleware) CreateCheckSum(req *http.Request, keyName string) string {
	h := md5.New()
	io.WriteString(h, req.Method)
	io.WriteString(h, "-")
	io.WriteString(h, req.URL.String())
	reqChecksum := hex.EncodeToString(h.Sum(nil))
	return m.Spec.APIID + keyName + reqChecksum
}

func (m *RedisCacheMiddleware) getTimeTTL(cacheTTL int64) string {
	timeNow := time.Now().Unix()
	newTTL := timeNow + cacheTTL
	asStr := strconv.Itoa(int(newTTL))
	return asStr
}

func (m *RedisCacheMiddleware) isTimeStampExpired(timestamp string) bool {
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

func (m *RedisCacheMiddleware) encodePayload(payload, timestamp string) string {
	sEnc := base64.StdEncoding.EncodeToString([]byte(payload))
	return sEnc + "|" + timestamp
}

func (m *RedisCacheMiddleware) decodePayload(payload string) (string, string, error) {
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

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *RedisCacheMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

	// Allow global cache disabe
	if !m.Spec.CacheOptions.EnableCache {
		return nil, 200
	}
	// Only allow idempotent (safe) methods
	if r.Method != "GET" && r.Method != "HEAD" {
		return nil, 200
	}

	var stat RequestStatus
	var isVirtual bool
	// Lets see if we can throw a sledgehammer at this
	if m.Spec.CacheOptions.CacheAllSafeRequests {
		stat = StatusCached
	} else {
		// New request checker, more targeted, less likely to fail
		_, versionPaths, _, _ := m.TykMiddleware.Spec.GetVersionData(r)
		found, _ := m.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, Cached)
		isVirtual, _ = m.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, VirtualPath)
		if found {
			stat = StatusCached
		}
	}

	// Cached route matched, let go
	if stat != StatusCached {
		return nil, 200
	}
	token := ctxGetAuthToken(r)

	// No authentication data? use the IP.
	if token == "" {
		token = GetIPFromRequest(r)
	}

	var copiedRequest *http.Request
	if RecordDetail(r) {
		copiedRequest = CopyHttpRequest(r)
	}

	key := m.CreateCheckSum(r, token)
	retBlob, found := m.CacheStore.GetKey(key)
	if found != nil {
		log.Debug("Cache enabled, but record not found")
		// Pass through to proxy AND CACHE RESULT

		var reqVal *http.Response
		if isVirtual {
			log.Debug("This is a virtual function")
			vp := VirtualEndpoint{TykMiddleware: m.TykMiddleware}
			vp.New()
			reqVal = vp.ServeHTTPForCache(w, r)
		} else {
			// This passes through and will write the value to the writer, but spit out a copy for the cache
			log.Debug("Not virtual, passing")
			reqVal = m.sh.ServeHTTPWithCache(w, r)
		}

		cacheThisRequest := true
		cacheTTL := m.Spec.CacheOptions.CacheTimeout

		if reqVal == nil {
			log.Warning("Upstream request must have failed, response is empty")
			return nil, 200
		}

		// make sure the status codes match if specified
		if len(m.Spec.CacheOptions.CacheOnlyResponseCodes) > 0 {
			foundCode := false
			for _, code := range m.Spec.CacheOptions.CacheOnlyResponseCodes {
				if code == reqVal.StatusCode {
					foundCode = true
					break
				}
			}
			if !foundCode {
				cacheThisRequest = false
			}
		}

		// Are we using upstream cache control?
		if m.Spec.CacheOptions.EnableUpstreamCacheControl {
			log.Debug("Upstream control enabled")
			// Do we cache?
			if reqVal.Header.Get(upstreamCacheHeader) == "" {
				log.Warning("Upstream cache action not found, not caching")
				cacheThisRequest = false
			}
			// Do we override TTL?
			ttl := reqVal.Header.Get(upstreamCacheTTLHeader)
			if ttl != "" {
				log.Debug("TTL Set upstream")
				cacheAsInt, err := strconv.Atoi(ttl)
				if err != nil {
					log.Error("Failed to decode TTL cache value: ", err)
					cacheTTL = m.Spec.CacheOptions.CacheTimeout
				} else {
					cacheTTL = int64(cacheAsInt)
				}
			}
		}

		if cacheThisRequest {
			log.Debug("Caching request to redis")
			var wireFormatReq bytes.Buffer
			reqVal.Write(&wireFormatReq)
			log.Debug("Cache TTL is:", cacheTTL)
			ts := m.getTimeTTL(cacheTTL)
			toStore := m.encodePayload(wireFormatReq.String(), ts)
			go m.CacheStore.SetKey(key, toStore, cacheTTL)

		}
		return nil, 666

	}

	cachedData, timestamp, err := m.decodePayload(retBlob)
	if err != nil {
		// Tere was an issue with this cache entry - lets remove it:
		m.CacheStore.DeleteKey(key)
		return nil, 200
	}

	if m.isTimeStampExpired(timestamp) || len(cachedData) == 0 {
		m.CacheStore.DeleteKey(key)
		return nil, 200
	}

	log.Debug("Cache got: ", cachedData)
	bufData := bufio.NewReader(strings.NewReader(cachedData))
	newRes, err := http.ReadResponse(bufData, r)
	if err != nil {
		log.Error("Could not create response object: ", err)
	}

	defer newRes.Body.Close()
	for _, h := range hopHeaders {
		newRes.Header.Del(h)
	}

	copyHeader(w.Header(), newRes.Header)
	session := ctxGetSession(r)

	// Only add ratelimit data to keyed sessions
	if session != nil {
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(int(session.QuotaMax)))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(int(session.QuotaRemaining)))
		w.Header().Set("X-RateLimit-Reset", strconv.Itoa(int(session.QuotaRenews)))
	}
	w.Header().Add("x-tyk-cached-response", "1")
	w.WriteHeader(newRes.StatusCode)
	m.Proxy.CopyResponse(w, newRes.Body)

	// Record analytics
	if !m.Spec.DoNotTrack {
		go m.sh.RecordHit(r, 0, newRes.StatusCode, copiedRequest, nil)
	}

	// Stop any further execution
	return nil, 666
}
