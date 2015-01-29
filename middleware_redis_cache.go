package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"github.com/gorilla/context"
	"io"
	"net/http"
	"strconv"
)

// RedisCacheMiddleware is a caching middleware that will pull data from Redis instead of the upstream proxy
type RedisCacheMiddleware struct {
	TykMiddleware
	CacheStore StorageHandler
}

type RedisCacheMiddlewareConfig struct{}

// New lets you do any initialisations for the object can be done here
func (m *RedisCacheMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *RedisCacheMiddleware) GetConfig() (interface{}, error) {
	var thisModuleConfig RedisCacheMiddlewareConfig
	return thisModuleConfig, nil
}

func (m RedisCacheMiddleware) CreateCheckSum(req *http.Request) string {
	h := md5.New()
	io.WriteString(h, req.URL.RawQuery)
	reqChecksum := hex.EncodeToString(h.Sum(nil))

	cacheKey := m.Spec.APIDefinition.APIID + reqChecksum

	return cacheKey
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *RedisCacheMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

	// Allow global cache disabe
	if !m.Spec.APIDefinition.CacheOptions.EenableCache {
		return nil, 200
	}

	// Only allow idempotent (safe) methods
	if r.Method != "GET" || r.Method != "OPTIONS" || r.Method != "HEAD" {
		return nil, 200
	}

	// We use the versioning middleware to get our status, this may be overkill
	_, stat, _ := m.TykMiddleware.Spec.IsRequestValid(r)

	// Cached route matched, let go
	if stat == StatusCached {
		thisKey := m.CreateCheckSum(r)
		retBlob, found := m.CacheStore.GetKey(thisKey)
		if found != nil {
			// Pass through to proxy AND CACHE RESULT
			sNP := SuccessHandler{m.TykMiddleware}
			reqVal := sNP.ServeHTTP(w, r)

			var wireFormatReq bytes.Buffer
			reqVal.Write(&wireFormatReq)

			m.CacheStore.SetKey(thisKey, wireFormatReq.String(), m.Spec.APIDefinition.CacheOptions.CacheTimeout)
			return nil, 666
		}

		retObj := bytes.NewReader([]byte(retBlob))

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
		w.Header().Add("x-tyk-cached-response", "1")
		thisSessionState := context.Get(r, SessionData).(SessionState)
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(int(thisSessionState.QuotaMax)))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(int(thisSessionState.QuotaRemaining)))
		w.Header().Set("X-RateLimit-Reset", strconv.Itoa(int(thisSessionState.QuotaRenews)))

		w.WriteHeader(newRes.StatusCode)
		m.Proxy.copyResponse(w, newRes.Body)

		// Record analytics
		sNP := SuccessHandler{m.TykMiddleware}
		sNP.RecordHit(w, r, 0)

		// Stop any further execution
		return nil, 666
	}

	return nil, 200
}
