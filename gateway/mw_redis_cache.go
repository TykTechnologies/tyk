package gateway

import (
	"bufio"
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

	"github.com/TykTechnologies/tyk-pump/analytics"

	"github.com/TykTechnologies/murmur3"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/storage"
)

const (
	cachedResponseHeader = "x-tyk-cached-response"
)

// RedisCacheMiddleware is a caching middleware that will pull data from Redis instead of the upstream proxy
type RedisCacheMiddleware struct {
	BaseMiddleware

	store storage.Handler
	sh    SuccessHandler
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
	req.Body = copyBody(req.Body, false)
	return ioutil.ReadAll(req.Body)
}

func isBodyHashRequired(request *http.Request) bool {
	return request.Body != nil &&
		(request.Method == http.MethodPost ||
			request.Method == http.MethodPut ||
			request.Method == http.MethodPatch)

}

func (m *RedisCacheMiddleware) isTimeStampExpired(timestamp string) bool {
	i, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		m.Logger().Error(err)
		return true
	}

	tm := time.Unix(i, 0)
	return tm.Before(time.Now())
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

// cacheOptions exists to transfer options from this middleware down the chain to the cache writer
type cacheOptions struct {
	key                    string
	cacheOnlyResponseCodes []int
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *RedisCacheMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	t1 := time.Now()

	var stat RequestStatus
	var cacheKeyRegex string
	var cacheMeta *EndPointCacheMeta

	version, _ := m.Spec.Version(r)
	versionPaths := m.Spec.RxPaths[version.Name]

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
		m.Logger().Debug("Not a cached path")
		return nil, http.StatusOK
	}
	token := ctxGetAuthToken(r)

	// No authentication data? use the IP.
	if token == "" {
		token = request.RealIP(r)
	}

	var retBlob string
	key, err := m.CreateCheckSum(r, token, cacheKeyRegex, m.getCacheKeyFromHeaders(r))
	if err != nil {
		m.Logger().Debug("Error creating checksum. Skipping cache check")
		return nil, http.StatusOK
	}

	cacheOnlyResponseCodes := m.Spec.CacheOptions.CacheOnlyResponseCodes
	// override api main CacheOnlyResponseCodes by endpoint specific if provided
	if cacheMeta != nil && len(cacheMeta.CacheOnlyResponseCodes) > 0 {
		cacheOnlyResponseCodes = cacheMeta.CacheOnlyResponseCodes
	}

	ctxSetCacheOptions(r, &cacheOptions{
		key:                    key,
		cacheOnlyResponseCodes: cacheOnlyResponseCodes,
	})

	retBlob, err = m.store.GetKey(key)
	if err != nil {
		// Record not found, continue with the middleware chain
		return nil, http.StatusOK
	}

	cachedData, timestamp, err := m.decodePayload(retBlob)
	if err != nil {
		// Tere was an issue with this cache entry - lets remove it:
		m.store.DeleteKey(key)
		return nil, http.StatusOK
	}

	if m.isTimeStampExpired(timestamp) || len(cachedData) == 0 {
		m.store.DeleteKey(key)
		return nil, http.StatusOK
	}

	bufData := bufio.NewReader(strings.NewReader(cachedData))
	newRes, err := http.ReadResponse(bufData, r)
	if err != nil {
		m.Logger().WithError(err).Error("Could not create response object")
		m.store.DeleteKey(key)
		return nil, http.StatusOK
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
		w.Header().Set(header.XRateLimitLimit, strconv.Itoa(int(quotaMax)))
		w.Header().Set(header.XRateLimitRemaining, strconv.Itoa(int(quotaRemaining)))
		w.Header().Set(header.XRateLimitReset, strconv.Itoa(int(quotaRenews)))
	}
	w.Header().Set(cachedResponseHeader, "1")

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
		ms := DurationToMillisecond(time.Since(t1))
		m.sh.RecordHit(r, analytics.Latency{Total: int64(ms)}, newRes.StatusCode, newRes)
	}

	// Stop any further execution after we wrote cache out
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
