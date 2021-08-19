package gateway

import (
	"bytes"
	"encoding/base64"
	"errors"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/config"

	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/request"
)

const (
	defaultTemplateName   = "error"
	defaultTemplateFormat = "json"
	defaultContentType    = headers.ApplicationJSON

	MsgAuthFieldMissing    = "Authorization field missing"
	MsgApiAccessDisallowed = "Access to this API has been disallowed"
	MsgBearerMailformed    = "Bearer token malformed"
	MsgKeyNotAuthorized    = "Key not authorised"
	MsgOauthClientRevoked  = "Key not authorised. OAuth client access was revoked"
)

var errCustomBodyResponse = errors.New("errCustomBodyResponse")

var TykErrors = make(map[string]config.TykError)

func errorAndStatusCode(errType string) (error, int) {
	err := TykErrors[errType]
	return errors.New(err.Message), err.Code
}

func defaultTykErrors() {
	TykErrors = make(map[string]config.TykError)
	TykErrors[ErrAuthAuthorizationFieldMissing] = config.TykError{
		Message: MsgAuthFieldMissing,
		Code:    http.StatusUnauthorized,
	}

	TykErrors[ErrAuthKeyNotFound] = config.TykError{
		Message: MsgApiAccessDisallowed,
		Code:    http.StatusForbidden,
	}

	TykErrors[ErrAuthCertNotFound] = config.TykError{
		Message: MsgApiAccessDisallowed,
		Code:    http.StatusForbidden,
	}

	TykErrors[ErrAuthKeyIsInvalid] = config.TykError{
		Message: MsgApiAccessDisallowed,
		Code:    http.StatusForbidden,
	}

	TykErrors[ErrOAuthAuthorizationFieldMissing] = config.TykError{
		Message: MsgAuthFieldMissing,
		Code:    http.StatusBadRequest,
	}

	TykErrors[ErrOAuthAuthorizationFieldMalformed] = config.TykError{
		Message: MsgBearerMailformed,
		Code:    http.StatusBadRequest,
	}

	TykErrors[ErrOAuthKeyNotFound] = config.TykError{
		Message: MsgKeyNotAuthorized,
		Code:    http.StatusForbidden,
	}

	TykErrors[ErrOAuthClientDeleted] = config.TykError{
		Message: MsgOauthClientRevoked,
		Code:    http.StatusForbidden,
	}
}

func overrideTykErrors() {
	for id, err := range config.Global().OverrideMessages {

		overridenErr := TykErrors[id]

		if err.Code != 0 {
			overridenErr.Code = err.Code
		}

		if err.Message != "" {
			overridenErr.Message = err.Message
		}

		TykErrors[id] = overridenErr
	}
}

// APIError is generic error object returned if there is something wrong with the request
type APIError struct {
	Message template.HTML
}

// ErrorHandler is invoked whenever there is an issue with a proxied request, most middleware will invoke
// the ErrorHandler if something is wrong with the request and halt the request processing through the chain
type ErrorHandler struct {
	BaseMiddleware
}

// TemplateExecutor is an interface used to switch between text/templates and html/template.
// It only switch to text/template (templatesRaw) when contentType is XML related
type TemplateExecutor interface {
	Execute(wr io.Writer, data interface{}) error
}

// HandleError is the actual error handler and will store the error details in analytics if analytics processing is enabled.
func (e *ErrorHandler) HandleError(w http.ResponseWriter, r *http.Request, errMsg string, errCode int, writeResponse bool) {
	defer e.Base().UpdateRequestSession(r)
	response := &http.Response{}

	if writeResponse {
		var templateExtension string
		contentType := r.Header.Get(headers.ContentType)
		contentType = strings.Split(contentType, ";")[0]

		switch contentType {
		case headers.ApplicationXML:
			templateExtension = "xml"
			contentType = headers.ApplicationXML
		case headers.TextXML:
			templateExtension = "xml"
			contentType = headers.TextXML
		default:
			templateExtension = "json"
			contentType = headers.ApplicationJSON
		}

		w.Header().Set(headers.ContentType, contentType)
		response.Header = http.Header{}
		response.Header.Set(headers.ContentType, contentType)
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
			response.Header.Set(headers.ContentType, defaultContentType)

		}

		//If the config option is not set or is false, add the header
		if !e.Spec.GlobalConfig.HideGeneratorHeader {
			w.Header().Add(headers.XGenerator, "tyk.io")
			response.Header.Add(headers.XGenerator, "tyk.io")
		}

		// Close connections
		if e.Spec.GlobalConfig.CloseConnections {
			w.Header().Add(headers.Connection, "close")
			response.Header.Add(headers.Connection, "close")

		}

		// If error is not customized write error in default way
		if errMsg != errCustomBodyResponse.Error() {
			w.WriteHeader(errCode)
			response.StatusCode = errCode
			var tmplExecutor TemplateExecutor
			tmplExecutor = tmpl

			apiError := APIError{template.HTML(template.JSEscapeString(errMsg))}
			if contentType == headers.ApplicationXML || contentType == headers.TextXML {
				apiError.Message = template.HTML(errMsg)

				//we look up in the last defined templateName to obtain the template.
				rawTmpl := templatesRaw.Lookup(templateName)
				tmplExecutor = rawTmpl
			}

			var log bytes.Buffer

			rsp := io.MultiWriter(w, &log)
			tmplExecutor.Execute(rsp, &apiError)
			response.Body = ioutil.NopCloser(&log)
		}
	}

	if memProfFile != nil {
		pprof.WriteHeapProfile(memProfFile)
	}

	if e.Spec.DoNotTrack || ctxGetDoNotTrack(r) {
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
		if recordDetail(r, e.Spec) {

			// Get the wire format representation

			var wireFormatReq bytes.Buffer
			r.Write(&wireFormatReq)
			rawRequest = base64.StdEncoding.EncodeToString(wireFormatReq.Bytes())

			var wireFormatRes bytes.Buffer
			response.Write(&wireFormatRes)
			rawResponse = base64.StdEncoding.EncodeToString(wireFormatRes.Bytes())

		}

		trackEP := false
		trackedPath := r.URL.Path
		if p := ctxGetTrackedPath(r); p != "" {
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
			Latency{},
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
