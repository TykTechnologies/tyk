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

	cache "github.com/pmylund/go-cache"

	"fmt"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
)

// Enums for keys to be stored in a session context - this is how gorilla expects
// these to be implemented and is lifted pretty much from docs
const (
	SessionData = iota
	AuthHeaderValue
	VersionData
	VersionDefault
	OrgSessionContext
	ContextData
	RetainHost
	TrackThisEndpoint
	DoNotTrackThisEndpoint
	UrlRewritePath
)

var SessionCache = cache.New(10*time.Second, 5*time.Second)
var ExpiryCache = cache.New(600*time.Second, 10*time.Minute)

type ReturningHttpHandler interface {
	ServeHTTP(http.ResponseWriter, *http.Request) *http.Response
	ServeHTTPForCache(http.ResponseWriter, *http.Request) *http.Response
	CopyResponse(io.Writer, io.Reader)
}

// SuccessHandler represents the final ServeHTTP() request for a proxied API request
type SuccessHandler struct {
	BaseMiddleware
}

func tagHeaders(r *http.Request, th []string, tags []string) []string {
	for k, v := range r.Header {
		cleanK := strings.ToLower(k)
		ok := false
		for _, hname := range th {
			if hname == cleanK {
				ok = true
				break
			}
		}

		if ok {
			for _, val := range v {
				tagName := fmt.Sprintf("%s-%s", cleanK, val)
				tags = append(tags, tagName)
			}
		}
	}

	return tags
}

func addVersionHeader(w http.ResponseWriter, r *http.Request) {
	if ctxGetDefaultVersion(r) {
		if vinfo := ctxGetVersionInfo(r); vinfo != nil {
			if config.Global.VersionHeader != "" {
				w.Header().Set(config.Global.VersionHeader, vinfo.Name)
			}
		}
	}
}

func (s *SuccessHandler) RecordHit(r *http.Request, timing int64, code int, requestCopy *http.Request, responseCopy *http.Response) {

	if s.Spec.DoNotTrack {
		return
	}

	ip := requestIP(r)
	if config.Global.StoreAnalytics(ip) {

		t := time.Now()

		// Track the key ID if it exists
		token := ctxGetAuthToken(r)

		// Track version data
		version := s.Spec.getVersionFromRequest(r)
		if version == "" {
			version = "Non Versioned"
		}

		// If OAuth, we need to grab it from the session, which may or may not exist
		oauthClientID := ""
		tags := make([]string, 0)
		var alias string
		session := ctxGetSession(r)

		if session != nil {
			oauthClientID = session.OauthClientID
			tags = session.Tags
			alias = session.Alias
		}

		if len(s.Spec.TagHeaders) > 0 {
			tags = tagHeaders(r, s.Spec.TagHeaders, tags)
		}

		rawRequest := ""
		rawResponse := ""

		if recordDetail(r) {
			// Get the wire format representation
			var wireFormatReq bytes.Buffer
			requestCopy.Write(&wireFormatReq)
			rawRequest = base64.StdEncoding.EncodeToString(wireFormatReq.Bytes())
			// responseCopy, unlike requestCopy, can be nil
			// here - if the response was cached in
			// mw_redis_cache, RecordHit gets passed a nil
			// response copy.
			// TODO: pass a copy of the cached response in
			// mw_redis_cache instead? is there a reason not
			// to include that in the analytics?
			if responseCopy != nil {
				// Get the wire format representation
				var wireFormatRes bytes.Buffer
				responseCopy.Write(&wireFormatRes)
				rawResponse = base64.StdEncoding.EncodeToString(wireFormatRes.Bytes())
			}
		}

		trackEP := false
		trackedPath := r.URL.Path
		if p := ctxGetTrackedPath(r); p != "" && !ctxGetDoNotTrack(r) {
			trackEP = true
			trackedPath = p
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
			token,
			t,
			version,
			s.Spec.Name,
			s.Spec.APIID,
			s.Spec.OrgID,
			oauthClientID,
			timing,
			rawRequest,
			rawResponse,
			ip,
			GeoData{},
			tags,
			alias,
			trackEP,
			time.Now(),
		}

		record.GetGeo(ip)

		expiresAfter := s.Spec.ExpireAnalyticsAfter
		if config.Global.EnforceOrgDataAge {
			orgExpireDataTime := s.OrgSessionExpiry(s.Spec.OrgID)

			if orgExpireDataTime > 0 {
				expiresAfter = orgExpireDataTime
			}
		}

		record.SetExpiry(expiresAfter)

		if config.Global.AnalyticsConfig.NormaliseUrls.Enabled {
			record.NormalisePath()
		}

		go analytics.RecordHit(record)
	}

	// Report in health check
	reportHealthValue(s.Spec, RequestLog, strconv.FormatInt(timing, 10))

	if memProfFile != nil {
		pprof.WriteHeapProfile(memProfFile)
	}
}

func recordDetail(r *http.Request) bool {
	// Are we even checking?
	if !config.Global.EnforceOrgDataDetailLogging {
		return config.Global.AnalyticsConfig.EnableDetailedRecording
	}

	// We are, so get session data
	ses := r.Context().Value(OrgSessionContext)
	if ses == nil {
		// no session found, use global config
		return config.Global.AnalyticsConfig.EnableDetailedRecording
	}

	// Session found
	return ses.(user.SessionState).EnableDetailedRecording
}

// ServeHTTP will store the request details in the analytics store if necessary and proxy the request to it's
// final destination, this is invoked by the ProxyHandler or right at the start of a request chain if the URL
// Spec states the path is Ignored
func (s *SuccessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) *http.Response {
	log.Debug("Started proxy")
	// Make sure we get the correct target URL
	if s.Spec.Proxy.StripListenPath {
		log.Debug("Stripping: ", s.Spec.Proxy.ListenPath)
		r.URL.Path = strings.Replace(r.URL.Path, s.Spec.Proxy.ListenPath, "", 1)
		r.URL.RawPath = strings.Replace(r.URL.RawPath, s.Spec.Proxy.ListenPath, "", 1)
		log.Debug("Upstream Path is: ", r.URL.Path)
	}

	addVersionHeader(w, r)

	var copiedRequest *http.Request
	if recordDetail(r) {
		copiedRequest = copyRequest(r)
	}

	t1 := time.Now()
	resp := s.Proxy.ServeHTTP(w, r)
	t2 := time.Now()

	millisec := float64(t2.UnixNano()-t1.UnixNano()) * 0.000001
	log.Debug("Upstream request took (ms): ", millisec)

	if resp != nil {
		var copiedResponse *http.Response
		if recordDetail(r) {
			copiedResponse = copyResponse(resp)
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
	if s.Spec.Proxy.StripListenPath {
		r.URL.Path = strings.Replace(r.URL.Path, s.Spec.Proxy.ListenPath, "", 1)
		r.URL.RawPath = strings.Replace(r.URL.RawPath, s.Spec.Proxy.ListenPath, "", 1)
	}

	var copiedRequest *http.Request
	if recordDetail(r) {
		copiedRequest = copyRequest(r)
	}

	t1 := time.Now()
	inRes := s.Proxy.ServeHTTPForCache(w, r)
	t2 := time.Now()

	addVersionHeader(w, r)

	var copiedResponse *http.Response
	if recordDetail(r) {
		copiedResponse = copyResponse(inRes)
	}

	millisec := float64(t2.UnixNano()-t1.UnixNano()) * 0.000001
	log.Debug("Upstream request took (ms): ", millisec)

	if inRes != nil {
		s.RecordHit(r, int64(millisec), inRes.StatusCode, copiedRequest, copiedResponse)
	}

	return inRes
}
