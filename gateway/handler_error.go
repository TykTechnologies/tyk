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
	"github.com/TykTechnologies/tyk/internal/httpctx"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
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

	latency := e.calculateErrorLatency(r)
	var responseBodyBytes []byte

	if e.Spec.IsMCP() && writeResponse && e.shouldWriteJSONRPCError(r) {
		response.StatusCode = errCode
		response.Header = http.Header{}
		response.Header.Set(header.ContentType, header.ApplicationJSON)

		responseBodyBytes = e.writeJSONRPCError(w, r, errMsg, errCode)
		response.Body = ioutil.NopCloser(bytes.NewReader(responseBodyBytes))

	} else if writeResponse {
		response.StatusCode = errCode
		templateExtension, contentType := e.getTemplateExtensionAndContentType(r)
		tmpl, templateName, finalContentType := e.findErrorTemplate(errCode, templateExtension, contentType)

		w.Header().Set(header.ContentType, finalContentType)
		response.Header = http.Header{}
		response.Header.Set(header.ContentType, finalContentType)

		if !e.Spec.GlobalConfig.HideGeneratorHeader {
			w.Header().Add(header.XGenerator, "tyk.io")
			response.Header.Add(header.XGenerator, "tyk.io")
		}

		if e.Spec.GlobalConfig.CloseConnections {
			w.Header().Add(header.Connection, "close")
			response.Header.Add(header.Connection, "close")
		}

		if errMsg != errCustomBodyResponse.Error() {
			w.WriteHeader(errCode)
			var tmplExecutor TemplateExecutor
			tmplExecutor = tmpl

			apiError := APIError{htmltemplate.HTML(htmltemplate.JSEscapeString(errMsg))}

			if contentType == header.ApplicationXML || contentType == header.TextXML {
				apiError.Message = htmltemplate.HTML(errMsg)

				rawTmpl := e.Gw.templatesRaw.Lookup(templateName)
				tmplExecutor = rawTmpl
			}

			var log bytes.Buffer

			rsp := io.MultiWriter(w, &log)
			tmplExecutor.Execute(rsp, &apiError)
			response.Body = ioutil.NopCloser(&log)
			responseBodyBytes = log.Bytes()
		}
	}

	if e.Spec.DoNotTrack || ctxGetDoNotTrack(r) {
		e.RecordAccessLog(r, response, latency)
		reportHealthValue(e.Spec, BlockedRequestLog, "-1")
		return
	}

	ip := request.RealIP(r)
	if e.Spec.GlobalConfig.StoreAnalytics(ip) {
		addVersionHeader(w, r, e.Spec.GlobalConfig)
		e.recordErrorAnalytics(r, response, responseBodyBytes, latency, errCode)
	}

	e.RecordAccessLog(r, response, latency)
	reportHealthValue(e.Spec, BlockedRequestLog, "-1")
}

// shouldWriteJSONRPCError returns true if this error should be formatted as JSON-RPC.
func (e *ErrorHandler) shouldWriteJSONRPCError(r *http.Request) bool {
	if e.Spec.JsonRpcVersion != apidef.JsonRPC20 {
		return false
	}

	routingState := httpctx.GetJSONRPCRoutingState(r)
	return routingState != nil
}

// calculateErrorLatency calculates latency for error responses.
// For errors, upstream latency is 0 since no successful upstream response occurred.
func (e *ErrorHandler) calculateErrorLatency(r *http.Request) analytics.Latency {
	var latency analytics.Latency
	if requestStartTime := ctxGetRequestStartTime(r); !requestStartTime.IsZero() {
		totalMs := int64(DurationToMillisecond(time.Since(requestStartTime)))
		latency = analytics.Latency{
			Total:    totalMs,
			Upstream: 0,       // No successful upstream response for errors
			Gateway:  totalMs, // All time is gateway time for errors
		}
	}
	return latency
}

// getTemplateExtensionAndContentType determines the template extension and content type
// based on the request's Content-Type header.
func (e *ErrorHandler) getTemplateExtensionAndContentType(r *http.Request) (string, string) {
	contentType := r.Header.Get(header.ContentType)
	contentType = strings.Split(contentType, ";")[0]

	switch contentType {
	case header.ApplicationXML:
		return "xml", header.ApplicationXML
	case header.TextXML:
		return "xml", header.TextXML
	default:
		return "json", header.ApplicationJSON
	}
}

// findErrorTemplate finds an appropriate error template using a fallback chain:
// 1. Try error_{code}.{ext} (e.g., error_500.json)
// 2. Fallback to error.{ext} (e.g., error.json)
// 3. Final fallback to error.json with default content type
// Returns: (template, templateName, contentType)
func (e *ErrorHandler) findErrorTemplate(errCode int, templateExtension string, contentType string) (*htmltemplate.Template, string, string) {
	// Try to use an error template that matches the HTTP error code and the content type
	templateName := "error_" + strconv.Itoa(errCode) + "." + templateExtension
	tmpl := e.Gw.templates.Lookup(templateName)

	// Fallback to a generic error template, but match the content type
	if tmpl == nil {
		templateName = defaultTemplateName + "." + templateExtension
		tmpl = e.Gw.templates.Lookup(templateName)
	}

	// If no template is available for this content type, fallback to error.json
	if tmpl == nil {
		templateName = defaultTemplateName + "." + defaultTemplateFormat
		tmpl = e.Gw.templates.Lookup(templateName)
		contentType = defaultContentType
	}

	return tmpl, templateName, contentType
}

// writeJSONRPCError writes an error in JSON-RPC 2.0 format and returns the response body.
func (e *ErrorHandler) writeJSONRPCError(w http.ResponseWriter, r *http.Request, errMsg string, httpCode int) []byte {
	var requestID interface{}
	if state := httpctx.GetJSONRPCRoutingState(r); state != nil {
		requestID = state.ID
	}

	return jsonrpcerrors.WriteJSONRPCError(w, requestID, httpCode, errMsg)
}

func (e *ErrorHandler) recordErrorAnalytics(r *http.Request, response *http.Response, responseBody []byte, latency analytics.Latency, errCode int) {
	token := ctxGetAuthToken(r)
	var alias string
	ip := request.RealIP(r)

	if !e.Spec.GlobalConfig.StoreAnalytics(ip) {
		return
	}

	t := time.Now()

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
		RequestTime:   latency.Total,
		Latency:       latency,
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
