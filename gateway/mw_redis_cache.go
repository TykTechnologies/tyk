package gateway

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/TykTechnologies/murmur3"
	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/regexp"
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
	CacheStore   storage.Handler
	sh           SuccessHandler
	singleFlight singleflight.Group
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

func (m *RedisCacheMiddleware) CreateCheckSum(req *http.Request, keyName string, regex string) (string, error) {
	h := md5.New()
	io.WriteString(h, req.Method)
	io.WriteString(h, "-")
	io.WriteString(h, req.URL.String())
	if req.Method == http.MethodPost {
		if req.Body != nil {
			bodyBytes, err := ioutil.ReadAll(req.Body)

			if err != nil {
				return "", err
			}

			defer req.Body.Close()
			req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

			m := murmur3.New128()
			if regex == "" {
				io.WriteString(h, "-")
				m.Write(bodyBytes)
				io.WriteString(h, hex.EncodeToString(m.Sum(nil)))
			} else {
				r, err := regexp.Compile(regex)
				if err != nil {
					return "", err
				}
				match := r.Find(bodyBytes)
				if match != nil {
					io.WriteString(h, "-")
					m.Write(match)
					io.WriteString(h, hex.EncodeToString(m.Sum(nil)))
				}
			}
		}
	}

	reqChecksum := hex.EncodeToString(h.Sum(nil))
	return m.Spec.APIID + keyName + reqChecksum, nil
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
	if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" && r.Method != "POST" {
		return nil, http.StatusOK
	}

	var stat RequestStatus
	var cacheKeyRegex string

	_, versionPaths, _, _ := m.Spec.Version(r)
	isVirtual, _ := m.Spec.CheckSpecMatchesStatus(r, versionPaths, VirtualPath)

	// Lets see if we can throw a sledgehammer at this
	if m.Spec.CacheOptions.CacheAllSafeRequests && r.Method != "POST" {
		stat = StatusCached
	}
	if stat != StatusCached {
		// New request checker, more targeted, less likely to fail
		found, meta := m.Spec.CheckSpecMatchesStatus(r, versionPaths, Cached)
		if found {
			cacheMeta := meta.(*EndPointCacheMeta)
			stat = StatusCached
			cacheKeyRegex = cacheMeta.CacheKeyRegex
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

	var errCreatingChecksum bool
	var retBlob string
	key, err := m.CreateCheckSum(r, token, cacheKeyRegex)
	if err != nil {
		log.Debug("Error creating checksum. Skipping cache check")
		errCreatingChecksum = true
	} else {
		retBlob, err = m.CacheStore.GetKey(key)
		v, sfErr, _ := m.singleFlight.Do(key, func() (interface{}, error) {
			return m.CacheStore.GetKey(key)
		})
		retBlob = v.(string)
		err = sfErr
	}

	if err != nil {
		if !errCreatingChecksum {
			log.Debug("Cache enabled, but record not found")
		}
		// Pass through to proxy AND CACHE RESULT

		var resVal *http.Response
		if isVirtual {
			log.Debug("This is a virtual function")
			vp := VirtualEndpoint{BaseMiddleware: m.BaseMiddleware}
			vp.Init()
			resVal = vp.ServeHTTPForCache(w, r, nil)
		} else {
			// This passes through and will write the value to the writer, but spit out a copy for the cache
			log.Debug("Not virtual, passing")
			resVal = m.sh.ServeHTTPWithCache(w, r)
		}

		cacheThisRequest := true
		cacheTTL := m.Spec.CacheOptions.CacheTimeout

		if resVal == nil {
			log.Warning("Upstream request must have failed, response is empty")
			return nil, http.StatusOK
		}

		// make sure the status codes match if specified
		if len(m.Spec.CacheOptions.CacheOnlyResponseCodes) > 0 {
			foundCode := false
			for _, code := range m.Spec.CacheOptions.CacheOnlyResponseCodes {
				if code == resVal.StatusCode {
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
			if resVal.Header.Get(upstreamCacheHeader) == "" {
				log.Warning("Upstream cache action not found, not caching")
				cacheThisRequest = false
			}

			cacheTTLHeader := upstreamCacheTTLHeader
			if m.Spec.CacheOptions.CacheControlTTLHeader != "" {
				cacheTTLHeader = m.Spec.CacheOptions.CacheControlTTLHeader
			}

			ttl := resVal.Header.Get(cacheTTLHeader)
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

		if cacheThisRequest && !errCreatingChecksum {
			log.Debug("Caching request to redis")
			var wireFormatReq bytes.Buffer
			resVal.Write(&wireFormatReq)
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
	nopCloseResponseBody(newRes)

	defer newRes.Body.Close()
	for _, h := range hopHeaders {
		newRes.Header.Del(h)
	}

	copyHeader(w.Header(), newRes.Header)
	session := ctxGetSession(r)

	// Only add ratelimit data to keyed sessions
	if session != nil {
		quotaMax, quotaRemaining, _, quotaRenews := session.GetQuotaLimitByAPIID(m.Spec.APIID)
		w.Header().Set(headers.XRateLimitLimit, strconv.Itoa(int(quotaMax)))
		w.Header().Set(headers.XRateLimitRemaining, strconv.Itoa(int(quotaRemaining)))
		w.Header().Set(headers.XRateLimitReset, strconv.Itoa(int(quotaRenews)))
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
		m.sh.RecordHit(r, 0, newRes.StatusCode, newRes)
	}

	// Stop any further execution
	return nil, mwStatusRespond
}
