package gateway

import (
	"bytes"
	"encoding/base64"
	"html/template"
	"net/http"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/request"
)

const (
	defaultTemplateName   = "error"
	defaultTemplateFormat = "json"
	defaultContentType    = headers.ApplicationJSON
)

// APIError is generic error object returned if there is something wrong with the request
type APIError struct {
	Message template.HTML
}

// ErrorHandler is invoked whenever there is an issue with a proxied request, most middleware will invoke
// the ErrorHandler if something is wrong with the request and halt the request processing through the chain
type ErrorHandler struct {
	BaseMiddleware
}

// HandleError is the actual error handler and will store the error details in analytics if analytics processing is enabled.
func (e *ErrorHandler) HandleError(w http.ResponseWriter, r *http.Request, errMsg string, errCode int, writeResponse bool) {
	defer e.Base().UpdateRequestSession(r)

	if writeResponse {
		var templateExtension string
		var contentType string

		switch r.Header.Get(headers.ContentType) {
		case headers.ApplicationXML:
			templateExtension = "xml"
			contentType = headers.ApplicationXML
		default:
			templateExtension = "json"
			contentType = headers.ApplicationJSON
		}

		w.Header().Set(headers.ContentType, contentType)

		templateName := "error_" + strconv.Itoa(errCode) + "." + templateExtension

		// Try to use an error template that matches the HTTP error code and the content type: 500.json, 400.xml, etc.
		tmpl := templates.Lookup(templateName)

		// Fallback to a generic error template, but match the content type: error.json, error.xml, etc.
		if tmpl == nil {
			templateName = defaultTemplateName + "." + templateExtension
			tmpl = templates.Lookup(templateName)
		}

		// If no template is available for this content type, fallback to "error.json".
		if tmpl == nil {
			templateName = defaultTemplateName + "." + defaultTemplateFormat
			tmpl = templates.Lookup(templateName)
			w.Header().Set(headers.ContentType, defaultContentType)
		}

		//If the config option is not set or is false, add the header
		if !e.Spec.GlobalConfig.HideGeneratorHeader {
			w.Header().Add(headers.XGenerator, "tyk.io")
		}

		// Close connections
		if e.Spec.GlobalConfig.CloseConnections {
			w.Header().Add(headers.Connection, "close")
		}

		// Need to return the correct error code!
		w.WriteHeader(errCode)
		apiError := APIError{template.HTML(template.JSEscapeString(errMsg))}
		tmpl.Execute(w, &apiError)
	}

	if memProfFile != nil {
		pprof.WriteHeapProfile(memProfFile)
	}

	if e.Spec.DoNotTrack {
		return
	}

	// Track the key ID if it exists
	token := ctxGetAuthToken(r)
	var alias string

	ip := request.RealIP(r)
	if e.Spec.GlobalConfig.StoreAnalytics(ip) {
		t := time.Now()

		addVersionHeader(w, r, e.Spec.GlobalConfig)

		version := e.Spec.getVersionFromRequest(r)
		if version == "" {
			version = "Non Versioned"
		}

		if e.Spec.Proxy.StripListenPath {
			r.URL.Path = e.Spec.StripListenPath(r, r.URL.Path)
		}

		// This is an odd bugfix, will need further testing
		r.URL.Path = "/" + r.URL.Path
		if strings.HasPrefix(r.URL.Path, "//") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/")
		}

		oauthClientID := ""
		session := ctxGetSession(r)
		tags := make([]string, 0, estimateTagsCapacity(session, e.Spec))
		if session != nil {
			oauthClientID = session.OauthClientID
			alias = session.Alias
			tags = append(tags, getSessionTags(session)...)
		}

		if len(e.Spec.TagHeaders) > 0 {
			tags = tagHeaders(r, e.Spec.TagHeaders, tags)
		}

		rawRequest := ""
		rawResponse := ""
		if recordDetail(r, e.Spec.GlobalConfig) {
			// Get the wire format representation
			var wireFormatReq bytes.Buffer
			r.Write(&wireFormatReq)
			rawRequest = base64.StdEncoding.EncodeToString(wireFormatReq.Bytes())
		}

		trackEP := false
		trackedPath := r.URL.Path
		if p := ctxGetTrackedPath(r); p != "" && !ctxGetDoNotTrack(r) {
			trackEP = true
			trackedPath = p
		}

		host := r.URL.Host
		if host == "" && e.Spec.target != nil {
			host = e.Spec.target.Host
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
			errCode,
			token,
			t,
			version,
			e.Spec.Name,
			e.Spec.APIID,
			e.Spec.OrgID,
			oauthClientID,
			0,
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

		if e.Spec.GlobalConfig.AnalyticsConfig.EnableGeoIP {
			record.GetGeo(ip)
		}

		expiresAfter := e.Spec.ExpireAnalyticsAfter
		if e.Spec.GlobalConfig.EnforceOrgDataAge {
			orgExpireDataTime := e.OrgSessionExpiry(e.Spec.OrgID)

			if orgExpireDataTime > 0 {
				expiresAfter = orgExpireDataTime
			}

		}

		record.SetExpiry(expiresAfter)
		if e.Spec.GlobalConfig.AnalyticsConfig.NormaliseUrls.Enabled {
			record.NormalisePath(&e.Spec.GlobalConfig)
		}

		analytics.RecordHit(&record)
	}
	// Report in health check
	reportHealthValue(e.Spec, BlockedRequestLog, "-1")

	if memProfFile != nil {
		pprof.WriteHeapProfile(memProfFile)
	}
}
