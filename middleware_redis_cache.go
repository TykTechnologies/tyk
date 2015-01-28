package main

import (
	"crypto/md5"
	"encoding/hex"
	"gopkg.in/vmihailenco/msgpack.v2"
	"io"
	"net/http"
)

// RedisCacheMiddleware is a caching middleware that will pull data from Redis instead of the upstream proxy
type RedisCacheMiddleware struct {
	TykMiddleware
	CacheStore StorageHandler
}

type RedisCacheMiddlewareConfig struct{}

//type CachedResponse struct {
//	Headers map[string]string
//	Body    []byte
//	Code    int
//}

// New lets you do any initialisations for the object can be done here
func (m *RedisCacheMiddleware) New() {
	log.Info("CACHING MIDDLEWARE INITIALISED")

}

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

func (m *RedisCacheMiddleware) DoResponse(rw http.ResponseWriter, res *http.Response) {
	defer res.Body.Close()

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	//	// Add resource headers
	//	if sessVal != nil {
	//		// We have found a session, lets report back
	//		var thisSessionState SessionState
	//		thisSessionState = sessVal.(SessionState)
	//		res.Header.Add("X-RateLimit-Limit", strconv.Itoa(int(thisSessionState.QuotaMax)))
	//		res.Header.Add("X-RateLimit-Remaining", strconv.Itoa(int(thisSessionState.QuotaRemaining)))
	//		res.Header.Add("X-RateLimit-Reset", strconv.Itoa(int(thisSessionState.QuotaRenews)))
	//	}

	copyHeader(rw.Header(), res.Header)

	rw.WriteHeader(res.StatusCode)
	m.TykMiddleware.Proxy.copyResponse(rw, res.Body)
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *RedisCacheMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	// Re-use versioning code here, same mechanic, only interested in cached status though
	_, stat, _ := m.TykMiddleware.Spec.IsRequestValid(r)

	if stat == StatusCached {
		log.Info("Cached request detected")
		thisKey := m.CreateCheckSum(r)
		retBlob, found := m.CacheStore.GetKey(thisKey)
		if found != nil {
			log.Info("Key not found, proxying and saving")
			// Pass through to proxy AND CACHE RESULT
			sNP := SuccessHandler{m.TykMiddleware}
			reqVal := sNP.ServeHTTP(w, r)

			log.Warning(reqVal)

			// Marshal this
			asByte, encErr := msgpack.Marshal(reqVal)
			if encErr != nil {
				log.Error("Encoding FAILED")
				return nil, 666
			}

			// This doesn't quite work
			// TODO: Fix encoding of response objects
			m.CacheStore.SetKey(thisKey, string(asByte), 10)

			return nil, 666
		}

		// Decode retObj
		retObj := new(http.Response)
		decErr := msgpack.Unmarshal([]byte(retBlob), &retObj)

		if decErr != nil {
			log.Error("Cache failure, could not decode cached object: ", decErr)
			return nil, 200
		}

		//		if retObj.Headers != nil {
		//			for k, v := range retObj.Headers {
		//				w.Header().Add(k, v)
		//			}
		//		}

		log.Info("Cache response being written")
		w.Header().Add("x-tyk-cache-response", "1")
		//		// Return cached request
		//		w.Write(retObj.Body)

		m.DoResponse(w, retObj)

		// Record analytics
		sNP := SuccessHandler{m.TykMiddleware}
		sNP.RecordHit(w, r, 0)

		// Stop any further execution
		return nil, 666
	}
	log.Info("Not cached")

	return nil, 200
}
