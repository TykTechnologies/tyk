package main

import (
	"bytes"
	b64 "encoding/base64"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"net"
	"net/http"
	"runtime/pprof"
	"strings"
	"time"
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
func (e ErrorHandler) HandleError(w http.ResponseWriter, r *http.Request, err string, errCode int) {
	if e.Spec.DoNotTrack {
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

		OauthClientID := ""
		tags := make([]string, 0)
		thisSessionState := context.Get(r, SessionData)

		if thisSessionState != nil {
			OauthClientID = thisSessionState.(SessionState).OauthClientID
			alias = thisSessionState.(SessionState).Alias
			tags = thisSessionState.(SessionState).Tags
		}

		var requestCopy *http.Request
		if RecordDetail(r) {
			requestCopy = CopyHttpRequest(r)
		}

		rawRequest := ""
		rawResponse := ""
		if RecordDetail(r) {
			if requestCopy != nil {
				// Get the wire format representation
				var wireFormatReq bytes.Buffer
				requestCopy.Write(&wireFormatReq)
				rawRequest = b64.StdEncoding.EncodeToString(wireFormatReq.Bytes())
			}
		}

		thisRecord := AnalyticsRecord{
			r.Method,
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
			OauthClientID,
			0,
			rawRequest,
			rawResponse,
			GetIPFromRequest(r),
			GeoData{},
			tags,
			alias,
			time.Now(),
		}

		thisRecord.GetGeo(GetIPFromRequest(r))

		expiresAfter := e.Spec.ExpireAnalyticsAfter
		if config.EnforceOrgDataAge {
			thisOrg := e.Spec.OrgID
			orgSessionState, found := e.GetOrgSession(thisOrg)
			if found {
				if orgSessionState.DataExpires > 0 {
					expiresAfter = orgSessionState.DataExpires
				}
			}
		}

		thisRecord.SetExpiry(expiresAfter)
		go analytics.RecordHit(thisRecord)
	}

	// Report in health check
	ReportHealthCheckValue(e.Spec.Health, BlockedRequestLog, "-1")

	w.Header().Add("Content-Type", "application/json")

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

	var thisIP string
	if clientIP, _, derr := net.SplitHostPort(r.RemoteAddr); derr == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := r.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		thisIP = clientIP
	}
	log.WithFields(logrus.Fields{
		"prefix":      "gateway",
		"user_ip":     thisIP,
		"server_name": e.Spec.APIDefinition.Proxy.TargetURL,
		"user_id":     obfuscated,
		"org_id":      e.Spec.APIDefinition.OrgID,
		"api_id":      e.Spec.APIDefinition.APIID,
		"path":        r.URL.Path,
	}).Error("request error: ", err)

	log.Debug("Returning error header")
	w.WriteHeader(errCode)
	thisError := APIError{fmt.Sprintf("%s", err)}
	templates.ExecuteTemplate(w, "error.json", &thisError)
	if doMemoryProfile {
		pprof.WriteHeapProfile(profileFile)
	}

	// Clean up
	context.Clear(r)
}
