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

	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/storage"
)

const (
	upstreamCacheHeader    = "x-tyk-cache-action-set"
	upstreamCacheTTLHeader = "x-tyk-cache-action-set-ttl"
)

// RedisCacheMiddleware is a caching middleware that will pull data from Redis instead of the upstream proxy
type RedisCacheMiddleware struct {
	BaseMiddleware
	CacheStore storage.Handler
	sh         SuccessHandler
}

func (m *RedisCacheMiddleware) Name() string {
	return "RedisCacheMiddleware"
}

func (m *RedisCacheMiddleware) Init() {
	m.sh = SuccessHandler{m.BaseMiddleware}
}

func (m *RedisCacheMiddleware) EnabledForSpec() bool {
	return m.Spec.CacheOptions.EnableCache
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
func (m *RedisCacheMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	// Only allow idempotent (safe) methods
	if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
		return nil, http.StatusOK
	}

	var stat RequestStatus

	_, versionPaths, _, _ := m.Spec.Version(r)
	isVirtual, _ := m.Spec.CheckSpecMatchesStatus(r, versionPaths, VirtualPath)

	// Lets see if we can throw a sledgehammer at this
	if m.Spec.CacheOptions.CacheAllSafeRequests {
		stat = StatusCached
	} else {
		// New request checker, more targeted, less likely to fail
		found, _ := m.Spec.CheckSpecMatchesStatus(r, versionPaths, Cached)
		if found {
			stat = StatusCached
		}
	}

	// Cached route matched, let go
	if stat != StatusCached {
		return nil, http.StatusOK
	}
	token := ctxGetAuthToken(r)

	// No authentication data? use the IP.
	if token == "" {
		token = request.RealIP(r)
	}

	key := m.CreateCheckSum(r, token)
	retBlob, err := m.CacheStore.GetKey(key)
	if err != nil {
		log.Debug("Cache enabled, but record not found")
		// Pass through to proxy AND CACHE RESULT

		var reqVal *http.Response
		if isVirtual {
			log.Debug("This is a virtual function")
			vp := VirtualEndpoint{BaseMiddleware: m.BaseMiddleware}
			vp.Init()
			reqVal = vp.ServeHTTPForCache(w, r, nil)
		} else {
			// This passes through and will write the value to the writer, but spit out a copy for the cache
			log.Debug("Not virtual, passing")
			reqVal = m.sh.ServeHTTPWithCache(w, r)
		}

		cacheThisRequest := true
		cacheTTL := m.Spec.CacheOptions.CacheTimeout

		if reqVal == nil {
			log.Warning("Upstream request must have failed, response is empty")
			return nil, http.StatusOK
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

			cacheTTLHeader := upstreamCacheTTLHeader
			if m.Spec.CacheOptions.CacheControlTTLHeader != "" {
				cacheTTLHeader = m.Spec.CacheOptions.CacheControlTTLHeader
			}

			ttl := reqVal.Header.Get(cacheTTLHeader)
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

		return nil, mwStatusRespond
	}

	cachedData, timestamp, err := m.decodePayload(retBlob)
	if err != nil {
		// Tere was an issue with this cache entry - lets remove it:
		m.CacheStore.DeleteKey(key)
		return nil, http.StatusOK
	}

	if m.isTimeStampExpired(timestamp) || len(cachedData) == 0 {
		m.CacheStore.DeleteKey(key)
		return nil, http.StatusOK
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
	w.Header().Set("x-tyk-cached-response", "1")

	if reqEtag := r.Header.Get("If-None-Match"); reqEtag != "" {
		if respEtag := newRes.Header.Get("Etag"); respEtag != "" {
			if strings.Contains(reqEtag, respEtag) {
				newRes.StatusCode = http.StatusNotModified
			}
		}
	}

	w.WriteHeader(newRes.StatusCode)
	if newRes.StatusCode != http.StatusNotModified {
		m.Proxy.CopyResponse(w, newRes.Body)
	}

	// Record analytics
	if !m.Spec.DoNotTrack {
		go m.sh.RecordHit(r, 0, newRes.StatusCode, nil)
	}

	// Stop any further execution
	return nil, mwStatusRespond
}
