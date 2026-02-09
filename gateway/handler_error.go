package gateway

import (
	"bytes"
	"encoding/base64"
	"errors"
	htmltemplate "html/template"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/config"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/request"
)

const (
	defaultTemplateName   = "error"
	defaultTemplateFormat = "json"
	defaultContentType    = header.ApplicationJSON

	MsgAuthFieldMissing                        = "Authorization field missing"
	MsgApiAccessDisallowed                     = "Access to this API has been disallowed"
	MsgAuthCertRequired                        = "Client certificate required"
	MsgBearerMailformed                        = "Bearer token malformed"
	MsgKeyNotAuthorized                        = "Key not authorised"
	MsgOauthClientRevoked                      = "Key not authorised. OAuth client access was revoked"
	MsgKeyNotAuthorizedUnexpectedSigningMethod = "Key not authorized: Unexpected signing method"
	MsgCertificateExpired                      = "Certificate has expired"
)

var errCustomBodyResponse = errors.New("errCustomBodyResponse")

var TykErrors = make(map[string]config.TykError)

func errorAndStatusCode(errType string) (error, int) {
	err := TykErrors[errType]
	return errors.New(err.Message), err.Code
}

func defaultTykErrors() {
	TykErrors = make(map[string]config.TykError)

	initAuthKeyErrors()
	initOauth2KeyExistsErrors()
}

func overrideTykErrors(gw *Gateway) {
	gwConfig := gw.GetConfig()

	for id, err := range gwConfig.OverrideMessages {

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
	Message htmltemplate.HTML
}

// ErrorHandler is invoked whenever there is an issue with a proxied request, most middleware will invoke
// the ErrorHandler if something is wrong with the request and halt the request processing through the chain
type ErrorHandler struct {
	*BaseMiddleware
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
		contentType := r.Header.Get(header.ContentType)
		contentType = strings.Split(contentType, ";")[0]

		switch contentType {
		case header.ApplicationXML:
			templateExtension = "xml"
			contentType = header.ApplicationXML
		case header.TextXML:
			templateExtension = "xml"
			contentType = header.TextXML
		default:
			templateExtension = "json"
			contentType = header.ApplicationJSON
		}

		w.Header().Set(header.ContentType, contentType)
		response.Header = http.Header{}
		response.Header.Set(header.ContentType, contentType)
		templateName := "error_" + strconv.Itoa(errCode) + "." + templateExtension

		// Try to use an error template that matches the HTTP error code and the content type: 500.json, 400.xml, etc.
		tmpl := e.Gw.templates.Lookup(templateName)

		// Fallback to a generic error template, but match the content type: error.json, error.xml, etc.
		if tmpl == nil {
			templateName = defaultTemplateName + "." + templateExtension
			tmpl = e.Gw.templates.Lookup(templateName)
		}

		// If no template is available for this content type, fallback to "error.json".
		if tmpl == nil {
			templateName = defaultTemplateName + "." + defaultTemplateFormat
			tmpl = e.Gw.templates.Lookup(templateName)
			w.Header().Set(header.ContentType, defaultContentType)
			response.Header.Set(header.ContentType, defaultContentType)

		}

		//If the config option is not set or is false, add the header
		if !e.Spec.GlobalConfig.HideGeneratorHeader {
			w.Header().Add(header.XGenerator, "tyk.io")
			response.Header.Add(header.XGenerator, "tyk.io")
		}

		// Close connections
		if e.Spec.GlobalConfig.CloseConnections {
			w.Header().Add(header.Connection, "close")
			response.Header.Add(header.Connection, "close")

		}

		// If error is not customized write error in default way
		if errMsg != errCustomBodyResponse.Error() {
			w.WriteHeader(errCode)
			response.StatusCode = errCode
			var tmplExecutor TemplateExecutor
			tmplExecutor = tmpl

			apiError := APIError{htmltemplate.HTML(htmltemplate.JSEscapeString(errMsg))}

			if contentType == header.ApplicationXML || contentType == header.TextXML {
				apiError.Message = htmltemplate.HTML(errMsg)

				//we look up in the last defined templateName to obtain the template.
				rawTmpl := e.Gw.templatesRaw.Lookup(templateName)
				tmplExecutor = rawTmpl
			}

			var log bytes.Buffer

			rsp := io.MultiWriter(w, &log)
			tmplExecutor.Execute(rsp, &apiError)
			response.Body = ioutil.NopCloser(&log)
		}
	}

	// Record RED metrics for errors (before DoNotTrack check as metrics should always be recorded)
	e.recordREDMetrics(r, errCode)

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
			r.URL.Path = e.Spec.StripListenPath(r.URL.Path)
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

		if len(e.Spec.Tags) > 0 {
			tags = append(tags, e.Spec.Tags...)
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

		record := analytics.AnalyticsRecord{
			Method:        r.Method,
			Host:          host,
			Path:          trackedPath,
			RawPath:       r.URL.Path,
			ContentLength: r.ContentLength,
			UserAgent:     r.Header.Get(header.UserAgent),
			Day:           t.Day(),
			Month:         t.Month(),
			Year:          t.Year(),
			Hour:          t.Hour(),
			ResponseCode:  errCode,
			APIKey:        token,
			TimeStamp:     t,
			APIVersion:    version,
			APIName:       e.Spec.Name,
			APIID:         e.Spec.APIID,
			OrgID:         e.Spec.OrgID,
			OauthID:       oauthClientID,
			RequestTime:   0,
			Latency:       analytics.Latency{},
			IPAddress:     ip,
			Geo:           analytics.GeoData{},
			Network:       analytics.NetworkStats{},
			Tags:          tags,
			Alias:         alias,
			TrackPath:     trackEP,
			ExpireAt:      t,
		}
		recordGraphDetails(&record, r, response, e.Spec)

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

		record.RawRequest = rawRequest
		record.RawResponse = rawResponse

		if e.Spec.GlobalConfig.AnalyticsConfig.EnableGeoIP {
			record.GetGeo(ip, e.Gw.Analytics.GeoIPDB)
		}
		if e.Spec.GraphQL.Enabled && e.Spec.GraphQL.ExecutionMode != apidef.GraphQLExecutionModeSubgraph {
			record.Tags = append(record.Tags, "tyk-graph-analytics")
			record.ApiSchema = base64.StdEncoding.EncodeToString([]byte(e.Spec.GraphQL.Schema))
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
			NormalisePath(&record, &e.Spec.GlobalConfig)
		}

		if e.Spec.AnalyticsPlugin.Enabled {
			_ = e.Spec.AnalyticsPluginConfig.processRecord(&record)
		}

		err := e.Gw.Analytics.RecordHit(&record)

		if err != nil {
			log.WithError(err).Error("could not store analytic record")
		}
	}

	e.RecordAccessLog(r, response, analytics.Latency{})

	// Report in health check
	reportHealthValue(e.Spec, BlockedRequestLog, "-1")
}

// recordREDMetrics records Rate, Errors, and Duration metrics for error responses.
func (e *ErrorHandler) recordREDMetrics(r *http.Request, errCode int) {
	if e.Gw.MetricsRecorder == nil || !e.Gw.MetricsRecorder.Enabled() {
		return
	}

	// Calculate total latency from request start time
	var totalMs float64
	if requestStartTime := ctxGetRequestStartTime(r); !requestStartTime.IsZero() {
		totalMs = DurationToMillisecond(time.Since(requestStartTime))
	}

	e.Gw.MetricsRecorder.Record(r.Context(),
		otel.MetricAttributes{
			APIID:        e.Spec.APIID,
			APIName:      e.Spec.Name,
			OrgID:        e.Spec.OrgID,
			Method:       r.Method,
			Path:         e.Spec.Proxy.ListenPath,
			ResponseCode: errCode,
		},
		otel.MetricLatency{
			Total:    totalMs,
			Gateway:  totalMs, // For errors, gateway time equals total time
			Upstream: 0,       // No upstream for errors
		})
}
