package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/context"
	"github.com/pmylund/go-cache"
)

// Enums for keys to be stored in a session context - this is how gorilla expects
// these to be implemented and is lifted pretty much from docs
const (
	SessionData = iota
	AuthHeaderValue
	VersionData
	VersionKeyContext
	OrgSessionContext
	ContextData
	RetainHost
	TrackThisEndpoint
	DoNotTrackThisEndpoint
)

var SessionCache = cache.New(10*time.Second, 5*time.Second)
var ExpiryCache = cache.New(600*time.Second, 10*time.Minute)

type ReturningHttpHandler interface {
	ServeHTTP(http.ResponseWriter, *http.Request) *http.Response
	ServeHTTPForCache(http.ResponseWriter, *http.Request) *http.Response
	CopyResponse(io.Writer, io.Reader)
	New(interface{}, *APISpec) (TykResponseHandler, error)
}

// TykMiddleware wraps up the ApiSpec and Proxy objects to be included in a
// middleware handler, this can probably be handled better.
type TykMiddleware struct {
	Spec  *APISpec
	Proxy ReturningHttpHandler
}

func (t *TykMiddleware) GetOrgSession(key string) (SessionState, bool) {
	// Try and get the session from the session store
	session, found := t.Spec.OrgSessionManager.GetSessionDetail(key)
	if found {
		// If exists, assume it has been authorized and pass on
		if config.EnforceOrgDataAge {
			// We cache org expiry data
			log.Debug("Setting data expiry: ", session.OrgID)
			go t.SetOrgExpiry(session.OrgID, session.DataExpires)
		}
		return session, true
	}

	return session, found
}

func (t *TykMiddleware) SetOrgExpiry(orgid string, expiry int64) {
	ExpiryCache.Set(orgid, expiry, cache.DefaultExpiration)
}

func (t *TykMiddleware) GetOrgSessionExpiry(orgid string) int64 {
	log.Debug("Checking: ", orgid)
	cachedVal, found := ExpiryCache.Get(orgid)
	if !found {
		go t.GetOrgSession(orgid)
		log.Debug("no cached entry found, returning 7 days")
		return 604800
	}

	return cachedVal.(int64)
}

// ApplyPolicyIfExists will check if a policy is loaded, if it is, it will overwrite the session state to use the policy values
func (t *TykMiddleware) ApplyPolicyIfExists(key string, session *SessionState) {
	if session.ApplyPolicyID == "" {
		return
	}
	policy, ok := Policies[session.ApplyPolicyID]
	if !ok {
		return
	}
	// Check ownership, policy org owner must be the same as API,
	// otherwise youcould overwrite a session key with a policy from a different org!
	if policy.OrgID != t.Spec.APIDefinition.OrgID {
		log.Error("Attempting to apply policy from different organisation to key, skipping")
		return
	}

	if policy.Partitions.Quota || policy.Partitions.RateLimit || policy.Partitions.Acl {
		// This is a partitioned policy, only apply what is active
		if policy.Partitions.Quota {
			// Quotas
			session.QuotaMax = policy.QuotaMax
			session.QuotaRenewalRate = policy.QuotaRenewalRate
		}

		if policy.Partitions.RateLimit {
			// Rate limting
			session.Allowance = policy.Rate // This is a legacy thing, merely to make sure output is consistent. Needs to be purged
			session.Rate = policy.Rate
			session.Per = policy.Per
			if policy.LastUpdated != "" {
				session.LastUpdated = policy.LastUpdated
			}
		}

		if policy.Partitions.Acl {
			// ACL
			session.AccessRights = policy.AccessRights
			session.HMACEnabled = policy.HMACEnabled
		}

	} else {
		// This is not a partitioned policy, apply everything
		// Quotas
		session.QuotaMax = policy.QuotaMax
		session.QuotaRenewalRate = policy.QuotaRenewalRate

		// Rate limting
		session.Allowance = policy.Rate // This is a legacy thing, merely to make sure output is consistent. Needs to be purged
		session.Rate = policy.Rate
		session.Per = policy.Per
		if policy.LastUpdated != "" {
			session.LastUpdated = policy.LastUpdated
		}

		// ACL
		session.AccessRights = policy.AccessRights
		session.HMACEnabled = policy.HMACEnabled
	}

	// Required for all
	session.IsInactive = policy.IsInactive
	session.Tags = policy.Tags

	// Update the session in the session manager in case it gets called again
	t.Spec.SessionManager.UpdateSession(key, *session, GetLifetime(t.Spec, session))
}

// CheckSessionAndIdentityForValidKey will check first the Session store for a valid key, if not found, it will try
// the Auth Handler, if not found it will fail
func (t *TykMiddleware) CheckSessionAndIdentityForValidKey(key string) (SessionState, bool) {
	// Try and get the session from the session store
	log.Debug("Querying local cache")
	// Check in-memory cache
	if !config.LocalSessionCache.DisableCacheSessionState {
		cachedVal, found := SessionCache.Get(key)
		if found {
			log.Debug("--> Key found in local cache")
			session := cachedVal.(SessionState)
			t.ApplyPolicyIfExists(key, &session)
			return session, true
		}
	}

	// Check session store
	log.Debug("Querying keystore")
	session, found := t.Spec.SessionManager.GetSessionDetail(key)
	if found {
		// If exists, assume it has been authorized and pass on
		// cache it
		go SessionCache.Set(key, session, cache.DefaultExpiration)

		// Check for a policy, if there is a policy, pull it and overwrite the session values
		t.ApplyPolicyIfExists(key, &session)
		log.Debug("--> Got key")
		return session, true
	}

	log.Debug("Querying authstore")
	// 2. If not there, get it from the AuthorizationHandler
	session, found = t.Spec.AuthManager.IsKeyAuthorised(key)
	if found {
		// If not in Session, and got it from AuthHandler, create a session with a new TTL
		log.Info("Recreating session for key: ", key)

		// cache it
		go SessionCache.Set(key, session, cache.DefaultExpiration)

		// Check for a policy, if there is a policy, pull it and overwrite the session values
		t.ApplyPolicyIfExists(key, &session)

		log.Debug("Lifetime is: ", GetLifetime(t.Spec, &session))
		// Need to set this in order for the write to work!
		session.LastUpdated = time.Now().String()
		t.Spec.SessionManager.UpdateSession(key, session, GetLifetime(t.Spec, &session))
	}

	return session, found
}

// SuccessHandler represents the final ServeHTTP() request for a proxied API request
type SuccessHandler struct {
	*TykMiddleware
}

func (s *SuccessHandler) RecordHit(r *http.Request, timing int64, code int, requestCopy *http.Request, responseCopy *http.Response) {

	if s.Spec.DoNotTrack {
		return
	}

	if config.StoreAnalytics(r) {

		t := time.Now()

		// Track the key ID if it exists
		authHeaderValue := context.Get(r, AuthHeaderValue)
		keyName := ""
		if authHeaderValue != nil {
			keyName = authHeaderValue.(string)
		}

		// Track version data
		version := s.Spec.getVersionFromRequest(r)
		if version == "" {
			version = "Non Versioned"
		}

		// If OAuth, we need to grab it from the session, which may or may not exist
		oauthClientID := ""
		tags := make([]string, 0)
		var alias string
		sessionState := context.Get(r, SessionData)

		if sessionState != nil {
			oauthClientID = sessionState.(SessionState).OauthClientID
			tags = sessionState.(SessionState).Tags
			alias = sessionState.(SessionState).Alias
		}

		rawRequest := ""
		rawResponse := ""
		if RecordDetail(r) {
			// Get the wire format representation
			var wireFormatReq bytes.Buffer
			requestCopy.Write(&wireFormatReq)
			rawRequest = base64.StdEncoding.EncodeToString(wireFormatReq.Bytes())
			// Get the wire format representation
			var wireFormatRes bytes.Buffer
			responseCopy.Write(&wireFormatRes)
			rawResponse = base64.StdEncoding.EncodeToString(wireFormatRes.Bytes())
		}

		trackThisEndpoint, ok := context.GetOk(r, TrackThisEndpoint)
		trackedPath := r.URL.Path
		trackEP := false
		if ok {
			trackEP = true
			trackedPath = trackThisEndpoint.(string)
		}

		_, dnOk := context.GetOk(r, DoNotTrackThisEndpoint)
		if dnOk {
			trackEP = false
			trackedPath = r.URL.Path
		}

		record := AnalyticsRecord{
			r.Method,
			trackedPath,
			r.URL.Path,
			r.ContentLength,
			r.Header.Get("User-Agent"),
			t.Day(),
			t.Month(),
			t.Year(),
			t.Hour(),
			code,
			keyName,
			t,
			version,
			s.Spec.APIDefinition.Name,
			s.Spec.APIDefinition.APIID,
			s.Spec.APIDefinition.OrgID,
			oauthClientID,
			timing,
			rawRequest,
			rawResponse,
			GetIPFromRequest(r),
			GeoData{},
			tags,
			alias,
			trackEP,
			time.Now(),
		}

		record.GetGeo(GetIPFromRequest(r))

		expiresAfter := s.Spec.ExpireAnalyticsAfter
		if config.EnforceOrgDataAge {
			orgExpireDataTime := s.GetOrgSessionExpiry(s.Spec.OrgID)

			if orgExpireDataTime > 0 {
				expiresAfter = orgExpireDataTime
			}
		}

		record.SetExpiry(expiresAfter)

		if config.AnalyticsConfig.NormaliseUrls.Enabled {
			record.NormalisePath()
		}

		go analytics.RecordHit(record)
	}

	// Report in health check
	ReportHealthCheckValue(s.Spec.Health, RequestLog, strconv.FormatInt(timing, 10))

	if doMemoryProfile {
		pprof.WriteHeapProfile(memProfFile)
	}

	context.Clear(r)
}

// ServeHTTP will store the request details in the analytics store if necessary and proxy the request to it's
// final destination, this is invoked by the ProxyHandler or right at the start of a request chain if the URL
// Spec states the path is Ignored
func (s *SuccessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) *http.Response {
	log.Debug("Started proxy")
	// Make sure we get the correct target URL
	if s.Spec.APIDefinition.Proxy.StripListenPath {
		log.Debug("Stripping: ", s.Spec.Proxy.ListenPath)
		r.URL.Path = strings.Replace(r.URL.Path, s.Spec.Proxy.ListenPath, "", 1)
		log.Debug("Upstream Path is: ", r.URL.Path)
	}

	var copiedRequest *http.Request
	if RecordDetail(r) {
		copiedRequest = CopyHttpRequest(r)
	}

	t1 := time.Now()
	resp := s.Proxy.ServeHTTP(w, r)
	t2 := time.Now()

	millisec := float64(t2.UnixNano()-t1.UnixNano()) * 0.000001
	log.Debug("Upstream request took (ms): ", millisec)

	if resp != nil {
		var copiedResponse *http.Response
		if RecordDetail(r) {
			copiedResponse = CopyHttpResponse(resp)
		}
		s.RecordHit(r, int64(millisec), resp.StatusCode, copiedRequest, copiedResponse)
	}
	log.Debug("Done proxy")
	return nil
}

// ServeHTTPWithCache will store the request details in the analytics store if necessary and proxy the request to it's
// final destination, this is invoked by the ProxyHandler or right at the start of a request chain if the URL
// Spec states the path is Ignored Itwill also return a response object for the cache
func (s *SuccessHandler) ServeHTTPWithCache(w http.ResponseWriter, r *http.Request) *http.Response {
	// Make sure we get the correct target URL
	if s.Spec.APIDefinition.Proxy.StripListenPath {
		r.URL.Path = strings.Replace(r.URL.Path, s.Spec.Proxy.ListenPath, "", 1)
	}

	var copiedRequest *http.Request
	if RecordDetail(r) {
		copiedRequest = CopyHttpRequest(r)
	}

	t1 := time.Now()
	inRes := s.Proxy.ServeHTTPForCache(w, r)
	t2 := time.Now()

	var copiedResponse *http.Response
	if RecordDetail(r) {
		copiedResponse = CopyHttpResponse(inRes)
	}

	millisec := float64(t2.UnixNano()-t1.UnixNano()) * 0.000001
	log.Debug("Upstream request took (ms): ", millisec)

	if inRes != nil {
		s.RecordHit(r, int64(millisec), inRes.StatusCode, copiedRequest, copiedResponse)
	}

	return inRes
}
