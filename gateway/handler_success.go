package gateway

import (
	"bytes"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/http"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	cache "github.com/pmylund/go-cache"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/user"
)

const (
	keyDataDeveloperID    = "tyk_developer_id"
	keyDataDeveloperEmail = "tyk_developer_email"
)

var (
	// key session memory cache
	SessionCache = cache.New(10*time.Second, 5*time.Second)

	// org session memory cache
	ExpiryCache = cache.New(600*time.Second, 10*time.Minute)

	// memory cache to store arbitrary items
	UtilCache = cache.New(time.Hour, 10*time.Minute)
)

type ProxyResponse struct {
	Response *http.Response
	// UpstreamLatency the time it takes to do roundtrip to upstream. Total time
	// taken for the gateway to receive response from upstream host.
	UpstreamLatency time.Duration
}

type ReturningHttpHandler interface {
	ServeHTTP(http.ResponseWriter, *http.Request) ProxyResponse
	ServeHTTPForCache(http.ResponseWriter, *http.Request) ProxyResponse
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
				tagName := cleanK + "-" + val
				tags = append(tags, tagName)
			}
		}
	}

	return tags
}

func addVersionHeader(w http.ResponseWriter, r *http.Request, globalConf config.Config) {
	if ctxGetDefaultVersion(r) {
		if vinfo := ctxGetVersionInfo(r); vinfo != nil {
			if globalConf.VersionHeader != "" {
				w.Header().Set(globalConf.VersionHeader, vinfo.Name)
			}
		}
	}
}

func estimateTagsCapacity(session *user.SessionState, apiSpec *APISpec) int {
	size := 5 // that number of tags expected to be added at least before we record hit
	if session != nil {
		size += len(session.Tags)

		size += len(session.ApplyPolicies)

		if session.GetMetaData() != nil {
			if _, ok := session.GetMetaDataByKey(keyDataDeveloperID); ok {
				size += 1
			}
		}
	}

	if apiSpec.GlobalConfig.DBAppConfOptions.NodeIsSegmented {
		size += len(apiSpec.GlobalConfig.DBAppConfOptions.Tags)
	}

	size += len(apiSpec.TagHeaders)

	return size
}

func getSessionTags(session *user.SessionState) []string {
	tags := make([]string, 0, len(session.Tags)+len(session.ApplyPolicies)+1)

	// add policy IDs
	for _, polID := range session.ApplyPolicies {
		tags = append(tags, "pol-"+polID)
	}

	if session.GetMetaData() != nil {
		if developerID, ok := session.GetMetaData()[keyDataDeveloperID].(string); ok {
			tags = append(tags, "dev-"+developerID)
		}
	}

	tags = append(tags, session.Tags...)

	return tags
}

func (s *SuccessHandler) RecordHit(r *http.Request, timing Latency, code int, responseCopy *http.Response) {

	if s.Spec.DoNotTrack || ctxGetDoNotTrack(r) {
		return
	}

	ip := request.RealIP(r)
	if s.Spec.GlobalConfig.StoreAnalytics(ip) {

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
		var alias string
		session := ctxGetSession(r)
		tags := make([]string, 0, estimateTagsCapacity(session, s.Spec))
		if session != nil {
			oauthClientID = session.OauthClientID
			tags = append(tags, getSessionTags(session)...)
			alias = session.Alias
		}

		if len(s.Spec.TagHeaders) > 0 {
			tags = tagHeaders(r, s.Spec.TagHeaders, tags)
		}

		rawRequest := ""
		rawResponse := ""

		if recordDetail(r, s.Spec) {
			// Get the wire format representation
			var wireFormatReq bytes.Buffer
			r.Write(&wireFormatReq)
			rawRequest = base64.StdEncoding.EncodeToString(wireFormatReq.Bytes())
			// responseCopy, unlike requestCopy, can be nil
			// here - if the response was cached in
			// mw_redis_cache, RecordHit gets passed a nil
			// response copy.
			// TODO: pass a copy of the cached response in
			// mw_redis_cache instead? is there a reason not
			// to include that in the analytics?
			if responseCopy != nil {
				contents, err := ioutil.ReadAll(responseCopy.Body)
				if err != nil {
					log.Error("Couldn't read response body", err)
				}

				responseCopy.Body = respBodyReader(r, responseCopy)

				// Get the wire format representation
				var wireFormatRes bytes.Buffer
				responseCopy.Write(&wireFormatRes)
				responseCopy.Body = ioutil.NopCloser(bytes.NewBuffer(contents))
				rawResponse = base64.StdEncoding.EncodeToString(wireFormatRes.Bytes())
			}
		}

		trackEP := false
		trackedPath := r.URL.Path
		if p := ctxGetTrackedPath(r); p != "" {
			trackEP = true
			trackedPath = p
		}

		host := r.URL.Host
		if host == "" && s.Spec.target != nil {
			host = s.Spec.target.Host
		}

		record := AnalyticsRecord{
			r.Method,
			host,
			trackedPath,
			r.URL.Path,
			r.ContentLength,
			r.Header.Get(headers.UserAgent),
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
			timing.Total,
			timing,
			rawRequest,
			rawResponse,
			ip,
			GeoData{},
			NetworkStats{},
			tags,
			alias,
			trackEP,
			t,
		}

		if s.Spec.GlobalConfig.AnalyticsConfig.EnableGeoIP {
			record.GetGeo(ip)
		}

		expiresAfter := s.Spec.ExpireAnalyticsAfter
		if s.Spec.GlobalConfig.EnforceOrgDataAge {
			orgExpireDataTime := s.OrgSessionExpiry(s.Spec.OrgID)

			if orgExpireDataTime > 0 {
				expiresAfter = orgExpireDataTime
			}
		}

		record.SetExpiry(expiresAfter)

		if s.Spec.GlobalConfig.AnalyticsConfig.NormaliseUrls.Enabled {
			record.NormalisePath(&s.Spec.GlobalConfig)
		}

		analytics.RecordHit(&record)
	}

	// Report in health check
	reportHealthValue(s.Spec, RequestLog, strconv.FormatInt(timing.Total, 10))

	if memProfFile != nil {
		pprof.WriteHeapProfile(memProfFile)
	}
}

func recordDetail(r *http.Request, spec *APISpec) bool {
	if spec.EnableDetailedRecording {
		return true
	}

	session := ctxGetSession(r)
	if session != nil {
		if session.EnableDetailedRecording || session.EnableDetailRecording {
			return true
		}
	}

	// Are we even checking?
	if !spec.GlobalConfig.EnforceOrgDataDetailLogging {
		return spec.GlobalConfig.AnalyticsConfig.EnableDetailedRecording
	}

	// We are, so get session data
	ses := r.Context().Value(ctx.OrgSessionContext)
	if ses == nil {
		// no session found, use global config
		return spec.GlobalConfig.AnalyticsConfig.EnableDetailedRecording
	}

	// Session found
	sess := ses.(*user.SessionState)
	return sess.EnableDetailRecording || sess.EnableDetailedRecording
}

// ServeHTTP will store the request details in the analytics store if necessary and proxy the request to it's
// final destination, this is invoked by the ProxyHandler or right at the start of a request chain if the URL
// Spec states the path is Ignored
func (s *SuccessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) *http.Response {
	log.Debug("Started proxy")
	defer s.Base().UpdateRequestSession(r)

	versionDef := s.Spec.VersionDefinition
	if !s.Spec.VersionData.NotVersioned && versionDef.Location == "url" && versionDef.StripPath {
		part := s.Spec.getVersionFromRequest(r)

		log.Info("Stripping version from url: ", part)

		r.URL.Path = strings.Replace(r.URL.Path, part+"/", "", 1)
		r.URL.RawPath = strings.Replace(r.URL.RawPath, part+"/", "", 1)
	}

	// Make sure we get the correct target URL
	if s.Spec.Proxy.StripListenPath {
		log.Debug("Stripping: ", s.Spec.Proxy.ListenPath)
		r.URL.Path = s.Spec.StripListenPath(r, r.URL.Path)
		r.URL.RawPath = s.Spec.StripListenPath(r, r.URL.RawPath)
		log.Debug("Upstream Path is: ", r.URL.Path)
	}

	addVersionHeader(w, r, s.Spec.GlobalConfig)

	t1 := time.Now()
	resp := s.Proxy.ServeHTTP(w, r)

	millisec := DurationToMillisecond(time.Since(t1))
	log.Debug("Upstream request took (ms): ", millisec)

	if resp.Response != nil {
		latency := Latency{
			Total:    int64(millisec),
			Upstream: int64(DurationToMillisecond(resp.UpstreamLatency)),
		}
		s.RecordHit(r, latency, resp.Response.StatusCode, resp.Response)
	}
	log.Debug("Done proxy")
	return nil
}

// ServeHTTPWithCache will store the request details in the analytics store if necessary and proxy the request to it's
// final destination, this is invoked by the ProxyHandler or right at the start of a request chain if the URL
// Spec states the path is Ignored Itwill also return a response object for the cache
func (s *SuccessHandler) ServeHTTPWithCache(w http.ResponseWriter, r *http.Request) ProxyResponse {

	versionDef := s.Spec.VersionDefinition
	if !s.Spec.VersionData.NotVersioned && versionDef.Location == "url" && versionDef.StripPath {
		part := s.Spec.getVersionFromRequest(r)

		log.Debug("Stripping version from URL: ", part)

		r.URL.Path = strings.Replace(r.URL.Path, part+"/", "", 1)
		r.URL.RawPath = strings.Replace(r.URL.RawPath, part+"/", "", 1)
	}

	// Make sure we get the correct target URL
	if s.Spec.Proxy.StripListenPath {
		r.URL.Path = s.Spec.StripListenPath(r, r.URL.Path)
		r.URL.RawPath = s.Spec.StripListenPath(r, r.URL.RawPath)
	}

	t1 := time.Now()
	inRes := s.Proxy.ServeHTTPForCache(w, r)
	millisec := DurationToMillisecond(time.Since(t1))

	addVersionHeader(w, r, s.Spec.GlobalConfig)

	log.Debug("Upstream request took (ms): ", millisec)

	if inRes.Response != nil {
		latency := Latency{
			Total:    int64(millisec),
			Upstream: int64(DurationToMillisecond(inRes.UpstreamLatency)),
		}
		s.RecordHit(r, latency, inRes.Response.StatusCode, inRes.Response)
	}

	return inRes
}
