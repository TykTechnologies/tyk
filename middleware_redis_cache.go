package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	b64 "encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/context"
)

const (
	UPSTREAM_CACHE_HEADER_NAME     = "x-tyk-cache-action-set"
	UPSTREAM_CACHE_TTL_HEADER_NAME = "x-tyk-cache-action-set-ttl"
)

// RedisCacheMiddleware is a caching middleware that will pull data from Redis instead of the upstream proxy
type RedisCacheMiddleware struct {
	*TykMiddleware
	CacheStore StorageHandler
	sh         SuccessHandler
}

func (mw *RedisCacheMiddleware) GetName() string {
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
	for _, thisVersion := range m.TykMiddleware.Spec.VersionData.Versions {
		if len(thisVersion.ExtendedPaths.Cached) > 0 {
			used = true
		}
	}

	return used
}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *RedisCacheMiddleware) GetConfig() (interface{}, error) {
	var thisModuleConfig RedisCacheMiddlewareConfig
	return thisModuleConfig, nil
}

func (m RedisCacheMiddleware) CreateCheckSum(req *http.Request, keyName string) string {
	h := md5.New()
	toEncode := strings.Join([]string{req.Method, req.URL.String()}, "-")
	log.Debug("Cache encoding: ", toEncode)
	io.WriteString(h, toEncode)
	reqChecksum := hex.EncodeToString(h.Sum(nil))

	cacheKey := m.Spec.APIDefinition.APIID + keyName + reqChecksum

	return cacheKey
}

func GetIP(ip string) (string, error) {
	IPWithoutPort := strings.Split(ip, ":")

	if len(IPWithoutPort) > 1 {
		ip = IPWithoutPort[0]
	} else {
		if len(IPWithoutPort) == 1 {
			return ip, nil
		}
		log.Warning(IPWithoutPort)
		return ip, errors.New("IP Address malformed")
	}
	return ip, nil
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
	sEnc := b64.StdEncoding.EncodeToString([]byte(payload))
	return sEnc + "|" + timestamp
}

func (m *RedisCacheMiddleware) decodePayload(payload string) (string, string, error) {
	data := strings.Split(payload, "|")

	if len(data) == 1 {
		return data[0], "", nil
	}

	if len(data) == 2 {
		sDec, decodeErr := b64.StdEncoding.DecodeString(data[0])
		if decodeErr != nil {
			return "", "", decodeErr
		}

		return string(sDec), data[1], nil
	}

	return "", "", errors.New("Decoding failed, array length wrong")

}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *RedisCacheMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

	// Allow global cache disabe
	if !m.Spec.APIDefinition.CacheOptions.EnableCache {
		return nil, 200
	}

	var stat RequestStatus
	var isVirtual bool
	// Only allow idempotent (safe) methods
	if r.Method == "GET" || r.Method == "OPTIONS" || r.Method == "HEAD" {
		// Lets see if we can throw a sledgehammer at this
		if m.Spec.APIDefinition.CacheOptions.CacheAllSafeRequests {
			stat = StatusCached
		} else {
			// New request checker, more targetted, less likely to fail
			_, versionPaths, _, _ := m.TykMiddleware.Spec.GetVersionData(r)
			found, _ := m.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, Cached)
			isVirtual, _ = m.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, VirtualPath)
			if found {
				stat = StatusCached
			}
		}

		// Cached route matched, let go
		if stat == StatusCached {
			var authHeaderValue string
			authVal := context.Get(r, AuthHeaderValue)

			// No authentication data? use the IP.
			if authVal == nil {
				var err error
				if authHeaderValue, err = GetIP(GetIPFromRequest(r)); err != nil {
					log.Error(err)
					return nil, 200
				}
			} else {
				authHeaderValue = authVal.(string)
			}

			var copiedRequest *http.Request
			if RecordDetail(r) {
				copiedRequest = CopyHttpRequest(r)
			}

			thisKey := m.CreateCheckSum(r, authHeaderValue)
			retBlob, found := m.CacheStore.GetKey(thisKey)
			if found != nil {
				log.Debug("Cache enabled, but record not found")
				// Pass through to proxy AND CACHE RESULT

				var reqVal *http.Response
				if isVirtual {
					log.Debug("This is a virtual function")
					thisVP := VirtualEndpoint{TykMiddleware: m.TykMiddleware}
					thisVP.New()
					reqVal = thisVP.ServeHTTPForCache(w, r)
				} else {
					// This passes through and will write the value to the writer, but spit out a copy for the cache
					log.Debug("Not virtual, passing")
					reqVal = m.sh.ServeHTTPWithCache(w, r)
				}

				cacheThisRequest := true
				cacheTTL := m.Spec.APIDefinition.CacheOptions.CacheTimeout

				if reqVal == nil {
					log.Warning("Upstream request must have failed, response is empty")
					return nil, 200
				}

				// make sure the status codes match if specified
				if len(m.Spec.APIDefinition.CacheOptions.CacheOnlyResponseCodes) > 0 {
					foundCode := false
					for _, code := range m.Spec.APIDefinition.CacheOptions.CacheOnlyResponseCodes {
						if code == reqVal.StatusCode {
							cacheThisRequest = true
							foundCode = true
							break
						}
					}
					if !foundCode {
						cacheThisRequest = false
					}
				}

				// Are we using upstream cache control?
				if m.Spec.APIDefinition.CacheOptions.EnableUpstreamCacheControl {
					log.Debug("Upstream control enabled")
					// Do we cache?
					if reqVal.Header.Get(UPSTREAM_CACHE_HEADER_NAME) == "" {
						log.Warning("Upstream cache action not found, not caching")
						cacheThisRequest = false
					}
					// Do we override TTL?
					ttl := reqVal.Header.Get(UPSTREAM_CACHE_TTL_HEADER_NAME)
					if ttl != "" {
						log.Debug("TTL Set upstream")
						cacheAsInt, valErr := strconv.Atoi(ttl)
						if valErr != nil {
							log.Error("Failed to decode TTL cache value: ", valErr)
							cacheTTL = m.Spec.APIDefinition.CacheOptions.CacheTimeout
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
					go m.CacheStore.SetKey(thisKey, toStore, cacheTTL)

				}
				return nil, 666

			}

			cachedData, timestamp, decErr := m.decodePayload(retBlob)
			if decErr != nil {
				// Tere was an issue with this cache entry - lets remove it:
				m.CacheStore.DeleteKey(thisKey)
				return nil, 200
			}

			if m.isTimeStampExpired(timestamp) {
				m.CacheStore.DeleteKey(thisKey)
				return nil, 200
			}

			if len(cachedData) == 0 {
				m.CacheStore.DeleteKey(thisKey)
				return nil, 200
			}

			retObj := bytes.NewReader([]byte(cachedData))
			log.Debug("Cache got: ", cachedData)

			asBufioReader := bufio.NewReader(retObj)
			newRes, resErr := http.ReadResponse(asBufioReader, r)
			if resErr != nil {
				log.Error("Could not create response object: ", resErr)
			}

			defer newRes.Body.Close()
			for _, h := range hopHeaders {
				newRes.Header.Del(h)
			}

			copyHeader(w.Header(), newRes.Header)
			sessObj := context.Get(r, SessionData)
			var thisSessionState SessionState

			// Only add ratelimit data to keyed sessions
			if sessObj != nil {
				thisSessionState = sessObj.(SessionState)
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(int(thisSessionState.QuotaMax)))
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(int(thisSessionState.QuotaRemaining)))
				w.Header().Set("X-RateLimit-Reset", strconv.Itoa(int(thisSessionState.QuotaRenews)))
			}
			w.Header().Add("x-tyk-cached-response", "1")
			w.WriteHeader(newRes.StatusCode)
			m.Proxy.CopyResponse(w, newRes.Body)

			// Record analytics
			if !m.Spec.DoNotTrack {
				go m.sh.RecordHit(w, r, 0, newRes.StatusCode, copiedRequest, nil)
			}

			// Stop any further execution
			return nil, 666
		}
	}

	return nil, 200
}
