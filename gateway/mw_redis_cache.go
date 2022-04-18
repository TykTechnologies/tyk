package gateway

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/TykTechnologies/murmur3"
	"github.com/TykTechnologies/tyk/analytics"
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

func (m *RedisCacheMiddleware) CreateCheckSum(req *http.Request, keyName string, regex string, additionalKeyFromHeaders string) (string, error) {
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
	return m.Spec.APIID + keyName + reqChecksum, nil
}

func addBodyHash(req *http.Request, regex string, h hash.Hash) (err error) {
	if !isBodyHashRequired(req) {
		return nil
	}

	bodyBytes, err := readBody(req)
	if err != nil {
		return err
	}

	mur := murmur3.New128()
	if regex == "" {
		mur.Write(bodyBytes)
		io.WriteString(h, "-"+hex.EncodeToString(mur.Sum(nil)))
		return nil
	}
	r, err := regexp.Compile(regex)
	if err != nil {
		return err
	}

	if match := r.Find(bodyBytes); match != nil {
		mur.Write(match)
		io.WriteString(h, "-"+hex.EncodeToString(mur.Sum(nil)))
	}
	return nil
}

func readBody(req *http.Request) (bodyBytes []byte, err error) {
	if n, ok := req.Body.(nopCloser); ok {
		n.Seek(0, io.SeekStart)
		bodyBytes, err = ioutil.ReadAll(n)
		if err != nil {
			return nil, err
		}
		n.Seek(0, io.SeekStart) // reset for any next read.
		return
	}

	req.Body = copyBody(req.Body)
	bodyBytes, err = ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body.(nopCloser).Seek(0, io.SeekStart) // reset for any next read.
	return
}

func isBodyHashRequired(request *http.Request) bool {
	return request.Body != nil &&
		(request.Method == http.MethodPost ||
			request.Method == http.MethodPut ||
			request.Method == http.MethodPatch)

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
	var stat RequestStatus
	var cacheKeyRegex string
	var cacheMeta *EndPointCacheMeta

	version, _ := m.Spec.Version(r)
	versionPaths := m.Spec.RxPaths[version.Name]
	isVirtual, _ := m.Spec.CheckSpecMatchesStatus(r, versionPaths, VirtualPath)

	// Lets see if we can throw a sledgehammer at this
	if m.Spec.CacheOptions.CacheAllSafeRequests && isSafeMethod(r.Method) {
		stat = StatusCached
	}
	if stat != StatusCached {
		// New request checker, more targeted, less likely to fail
		found, meta := m.Spec.CheckSpecMatchesStatus(r, versionPaths, Cached)
		if found {
			cacheMeta = meta.(*EndPointCacheMeta)
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
	key, err := m.CreateCheckSum(r, token, cacheKeyRegex, m.getCacheKeyFromHeaders(r))
	if err != nil {
		log.Debug("Error creating checksum. Skipping cache check")
		errCreatingChecksum = true
	} else {
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
			if newURL := ctxGetURLRewriteTarget(r); newURL != nil {
				r.URL = newURL
				ctxSetURLRewriteTarget(r, nil)
			}
			if newMethod := ctxGetTransformRequestMethod(r); newMethod != "" {
				r.Method = newMethod
				ctxSetTransformRequestMethod(r, "")
			}
			sr := m.sh.ServeHTTPWithCache(w, r)
			resVal = sr.Response
		}

		cacheThisRequest := true
		cacheTTL := m.Spec.CacheOptions.CacheTimeout

		if resVal == nil {
			log.Warning("Upstream request must have failed, response is empty")
			return nil, mwStatusRespond
		}

		cacheOnlyResponseCodes := m.Spec.CacheOptions.CacheOnlyResponseCodes
		// override api main CacheOnlyResponseCodes by endpoint specific if provided
		if cacheMeta != nil && len(cacheMeta.CacheOnlyResponseCodes) > 0 {
			cacheOnlyResponseCodes = cacheMeta.CacheOnlyResponseCodes
		}

		// make sure the status codes match if specified
		if len(cacheOnlyResponseCodes) > 0 {
			foundCode := false
			for _, code := range cacheOnlyResponseCodes {
				if code == resVal.StatusCode {
					foundCode = true
					break
				}
			}
			cacheThisRequest = foundCode
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
			go func() {
				err := m.CacheStore.SetKey(key, toStore, cacheTTL)
				if err != nil {
					log.WithError(err).Error("could not save key in cache store")
				}
			}()
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

	copyHeader(w.Header(), newRes.Header, m.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey)
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
		m.Proxy.CopyResponse(w, newRes.Body, 0)
	}

	// Record analytics
	if !m.Spec.DoNotTrack {
		m.sh.RecordHit(r, analytics.Latency{}, newRes.StatusCode, newRes)
	}

	// Stop any further execution
	return nil, mwStatusRespond
}

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func (m *RedisCacheMiddleware) getCacheKeyFromHeaders(r *http.Request) (key string) {
	key = ""
	for _, header := range m.Spec.CacheOptions.CacheByHeaders {
		key += header + "-" + r.Header.Get(header)
	}
	return
}
