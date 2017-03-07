package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/context"

	"github.com/TykTechnologies/logrus"
)

const (
	defaultTemplateName   = "error"
	defaultTemplateFormat = "json"
	defaultContentType    = "application/json"
)

// APIError is generic error object returned if there is something wrong with the request
type APIError struct {
	Message string
}

// ErrorHandler is invoked whenever there is an issue with a proxied request, most middleware will invoke
// the ErrorHandler if something is wrong with the request and halt the request processing through the chain
type ErrorHandler struct {
	*TykMiddleware
}

// HandleError is the actual error handler and will store the error details in analytics if analytics processing is enabled.
func (e *ErrorHandler) HandleError(w http.ResponseWriter, r *http.Request, errMsg string, errCode int) {
	var templateExtension string
	var contentType string

	switch r.Header.Get("Content-Type") {
	case "application/xml":
		templateExtension = "xml"
		contentType = "application/xml"
	default:
		templateExtension = "json"
		contentType = "application/json"
	}

	w.Header().Set("Content-Type", contentType)

	templateName := fmt.Sprintf("error_%s.%s", strconv.Itoa(errCode), templateExtension)

	// Try to use an error template that matches the HTTP error code and the content type: 500.json, 400.xml, etc.
	tmpl := templates.Lookup(templateName)

	// Fallback to a generic error template, but match the content type: error.json, error.xml, etc.
	if tmpl == nil {
		templateName = fmt.Sprintf("%s.%s", defaultTemplateName, templateExtension)
		tmpl = templates.Lookup(templateName)
	}

	// If no template is available for this content type, fallback to "error.json".
	if tmpl == nil {
		templateName = fmt.Sprintf("%s.%s", defaultTemplateName, defaultTemplateFormat)
		tmpl = templates.Lookup(templateName)
		w.Header().Set("Content-Type", defaultContentType)
	}

	// Need to return the correct error code!
	w.WriteHeader(errCode)

	apiError := APIError{errMsg}
	tmpl.Execute(w, &apiError)

	if memProfFile != nil {
		pprof.WriteHeapProfile(memProfFile)
	}

	if e.Spec.DoNotTrack {
		context.Clear(r)
		return
	}

	keyName := ""
	// Track the key ID if it exists
	authHeaderValue := context.Get(r, AuthHeaderValue)
	var alias string

	if config.StoreAnalytics(r) {

		t := time.Now()

		if authHeaderValue != nil {
			keyName = authHeaderValue.(string)
		}

		version := e.Spec.getVersionFromRequest(r)
		if version == "" {
			version = "Non Versioned"
		}

		if e.TykMiddleware.Spec.APIDefinition.Proxy.StripListenPath {
			r.URL.Path = strings.Replace(r.URL.Path, e.TykMiddleware.Spec.Proxy.ListenPath, "", 1)
		}

		// This is an odd bugfix, will need further testing
		r.URL.Path = "/" + r.URL.Path
		if strings.HasPrefix(r.URL.Path, "//") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/")
		}

		oauthClientID := ""
		tags := make([]string, 0)
		sessionState := context.Get(r, SessionData)

		if sessionState != nil {
			oauthClientID = sessionState.(SessionState).OauthClientID
			alias = sessionState.(SessionState).Alias
			tags = sessionState.(SessionState).Tags
		}

		rawRequest := ""
		rawResponse := ""
		if RecordDetail(r) {
			requestCopy := CopyHttpRequest(r)
			// Get the wire format representation
			var wireFormatReq bytes.Buffer
			requestCopy.Write(&wireFormatReq)
			rawRequest = base64.StdEncoding.EncodeToString(wireFormatReq.Bytes())
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
			errCode,
			keyName,
			t,
			version,
			e.Spec.APIDefinition.Name,
			e.Spec.APIDefinition.APIID,
			e.Spec.APIDefinition.OrgID,
			oauthClientID,
			0,
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

		expiresAfter := e.Spec.ExpireAnalyticsAfter
		if config.EnforceOrgDataAge {
			orgExpireDataTime := e.GetOrgSessionExpiry(e.Spec.OrgID)

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
	ReportHealthCheckValue(e.Spec.Health, BlockedRequestLog, "-1")

	//If the config option is not set or is false, add the header
	if !config.HideGeneratorHeader {
		w.Header().Add("X-Generator", "tyk.io")
	}

	// Close connections
	if config.CloseConnections {
		w.Header().Add("Connection", "close")
	}

	var obfuscated string

	if len(keyName) > 4 {
		obfuscated = "****" + keyName[len(keyName)-4:]
	}

	// TODO: what is this bit of code for?
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := r.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
	} else {
		log.WithFields(logrus.Fields{
			"prefix":      "gateway",
			"user_ip":     r.RemoteAddr,
			"server_name": e.Spec.APIDefinition.Proxy.TargetURL,
			"user_id":     obfuscated,
			"org_id":      e.Spec.APIDefinition.OrgID,
			"api_id":      e.Spec.APIDefinition.APIID,
			"path":        r.URL.Path,
		}).Error("request error: ", err)
	}

	if memProfFile != nil {
		pprof.WriteHeapProfile(memProfFile)
	}

	// Clean up
	context.Clear(r)
}
