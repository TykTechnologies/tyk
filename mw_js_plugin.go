package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"github.com/TykTechnologies/tyk/user"
)

// Lets the user override and return a response from middleware
type ReturnOverrides struct {
	ResponseCode    int
	ResponseError   string
	ResponseHeaders map[string]string
}

// MiniRequestObject is marshalled to JSON string and passed into JSON middleware
type MiniRequestObject struct {
	Headers         map[string][]string
	SetHeaders      map[string]string
	DeleteHeaders   []string
	Body            []byte
	URL             string
	Params          map[string][]string
	AddParams       map[string]string
	ExtendedParams  map[string][]string
	DeleteParams    []string
	ReturnOverrides ReturnOverrides
	IgnoreBody      bool
	Method          string
	RequestURI      string
	Scheme          string
}

type VMReturnObject struct {
	Request     MiniRequestObject
	SessionMeta map[string]string
	Session     user.SessionState
	AuthValue   string
}

// DynamicMiddleware is a generic middleware that will execute JS code before continuing
type DynamicMiddleware struct {
	BaseMiddleware
	MiddlewareClassName string
	Pre                 bool
	UseSession          bool
	Auth                bool
}

func (d *DynamicMiddleware) Name() string {
	return "DynamicMiddleware"
}

func specToJson(spec *APISpec) string {
	m := map[string]interface{}{
		"OrgID": spec.OrgID,
		"APIID": spec.APIID,
		// For backwards compatibility within 2.x.
		// TODO: simplify or refactor in 3.x or later.
		"config_data": spec.ConfigData,
	}
	bs, err := json.Marshal(m)
	if err != nil {
		log.Error("Failed to encode configuration data: ", err)
		return ""
	}
	return string(bs)
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (d *DynamicMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	t1 := time.Now().UnixNano()
	logger := d.Logger()

	// Create the proxy object
	defer r.Body.Close()
	originalBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.WithError(err).Error("Failed to read request body")
		return nil, http.StatusOK
	}
	headers := r.Header
	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}
	if host != "" {
		headers = make(http.Header)
		for k, v := range r.Header {
			headers[k] = v
		}
		headers.Set("Host", host)
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	requestData := MiniRequestObject{
		Headers:        headers,
		SetHeaders:     map[string]string{},
		DeleteHeaders:  []string{},
		Body:           originalBody,
		URL:            r.URL.String(),
		Params:         r.URL.Query(),
		AddParams:      map[string]string{},
		ExtendedParams: map[string][]string{},
		DeleteParams:   []string{},
		Method:         r.Method,
		RequestURI:     r.RequestURI,
		Scheme:         scheme,
	}

	requestAsJson, err := json.Marshal(requestData)
	if err != nil {
		logger.WithError(err).Error("Failed to encode request object for dynamic middleware")
		return nil, http.StatusOK
	}

	specAsJson := specToJson(d.Spec)

	session := new(user.SessionState)

	// Encode the session object (if not a pre-process)
	if !d.Pre && d.UseSession {
		session = ctxGetSession(r)
	}

	sessionAsJson, err := json.Marshal(session)
	if err != nil {
		logger.WithError(err).Error("Failed to encode session for VM")
		return nil, http.StatusOK
	}

	// Run the middleware

	err, code, returnDataStr := d.Spec.JSVM.RunJSRequestDynamic(d, logger, string(requestAsJson), string(sessionAsJson), specAsJson)
	if err != nil {
		log.Errorf("JSVM error: %v", err)
	}

	if code != -1 {
		return nil, code
	}
	// Decode the return object
	newRequestData := VMReturnObject{}
	if err := json.Unmarshal([]byte(returnDataStr), &newRequestData); err != nil {
		logger.WithError(err).Error("Failed to decode middleware request data on return from VM. Returned data: ", returnDataStr)
		return nil, http.StatusOK
	}

	// Reconstruct the request parts
	if newRequestData.Request.IgnoreBody {
		r.ContentLength = int64(len(originalBody))
		r.Body = ioutil.NopCloser(bytes.NewReader(originalBody))
	} else {
		r.ContentLength = int64(len(newRequestData.Request.Body))
		r.Body = ioutil.NopCloser(bytes.NewReader(newRequestData.Request.Body))
	}

	r.URL, err = url.ParseRequestURI(newRequestData.Request.URL)
	if err != nil {
		return nil, http.StatusOK
	}

	// Delete and set headers
	for _, dh := range newRequestData.Request.DeleteHeaders {
		r.Header.Del(dh)
	}

	for h, v := range newRequestData.Request.SetHeaders {
		r.Header.Set(h, v)
	}

	// Delete and set request parameters
	values := r.URL.Query()
	for _, k := range newRequestData.Request.DeleteParams {
		values.Del(k)
	}

	for p, v := range newRequestData.Request.AddParams {
		values.Set(p, v)
	}

	for p, v := range newRequestData.Request.ExtendedParams {
		for _, val := range v {
			values.Add(p, val)
		}
	}

	r.URL.RawQuery = values.Encode()

	// Save the sesison data (if modified)
	if !d.Pre && d.UseSession {
		newMeta := mapStrsToIfaces(newRequestData.SessionMeta)
		if !reflect.DeepEqual(session.MetaData, newMeta) {
			session.MetaData = newMeta
			ctxScheduleSessionUpdate(r)
		}
	}

	logger.Debug("JSVM middleware execution took: (ns) ", time.Now().UnixNano()-t1)

	if newRequestData.Request.ReturnOverrides.ResponseCode >= http.StatusBadRequest {
		return errors.New(newRequestData.Request.ReturnOverrides.ResponseError), newRequestData.Request.ReturnOverrides.ResponseCode
	}

	if newRequestData.Request.ReturnOverrides.ResponseCode != 0 && newRequestData.Request.ReturnOverrides.ResponseCode < http.StatusMultipleChoices {

		responseObject := VMResponseObject{
			Response: ResponseObject{
				Body:    newRequestData.Request.ReturnOverrides.ResponseError,
				Code:    newRequestData.Request.ReturnOverrides.ResponseCode,
				Headers: newRequestData.Request.ReturnOverrides.ResponseHeaders,
			},
		}

		forceResponse(w, r, &responseObject, d.Spec, session, d.Pre, logger)
		return nil, mwStatusRespond
	}

	if d.Auth {
		ctxSetSession(r, &newRequestData.Session, newRequestData.AuthValue, true)
	}

	return nil, http.StatusOK
}

func mapStrsToIfaces(m map[string]string) map[string]interface{} {
	// TODO: do we really need this conversion? note that we can't
	// make user.SessionState.MetaData a map[string]string, however.
	m2 := make(map[string]interface{}, len(m))
	for k, v := range m {
		m2[k] = v
	}
	return m2
}

const coreJS = `
var TykJS = {
	TykMiddleware: {
		MiddlewareComponentMeta: function(configuration) {
			this.configuration = configuration
		}
	},
	TykEventHandlers: {
		EventHandlerComponentMeta: function() {}
	}
}

TykJS.TykMiddleware.MiddlewareComponentMeta.prototype.ProcessRequest = function(request, session, config) {
	log("Process Request Not Implemented")
	return request
}

TykJS.TykMiddleware.MiddlewareComponentMeta.prototype.DoProcessRequest = function(request, session, config) {
	request.Body = b64dec(request.Body)
	var processed_request = this.ProcessRequest(request, session, config)

	if (!processed_request) {
		log("Middleware didn't return request object!")
		return
	}

	// Reset the headers object
	processed_request.Request.Headers = {}
	processed_request.Request.Body = b64enc(processed_request.Request.Body)

	return JSON.stringify(processed_request)
}

// The user-level middleware component
TykJS.TykMiddleware.NewMiddleware = function(configuration) {
	TykJS.TykMiddleware.MiddlewareComponentMeta.call(this, configuration)
}

// Set up object inheritance
TykJS.TykMiddleware.NewMiddleware.prototype = Object.create(TykJS.TykMiddleware.MiddlewareComponentMeta.prototype)
TykJS.TykMiddleware.NewMiddleware.prototype.constructor = TykJS.TykMiddleware.NewMiddleware

TykJS.TykMiddleware.NewMiddleware.prototype.NewProcessRequest = function(callback) {
	this.ProcessRequest = callback
}

TykJS.TykMiddleware.NewMiddleware.prototype.ReturnData = function(request, session) {
	return {Request: request, SessionMeta: session}
}

TykJS.TykMiddleware.NewMiddleware.prototype.ReturnAuthData = function(request, session) {
	return {Request: request, Session: session}
}

// Event Handler implementation

TykJS.TykEventHandlers.EventHandlerComponentMeta.prototype.DoProcessEvent = function(event, context) {
	// call the handler
	log("Calling built - in handle")
	this.Handle(event, context)
	return
}

TykJS.TykEventHandlers.EventHandlerComponentMeta.prototype.Handle = function(request, context) {
	log("Handler not implemented!")
	return request
}

// The user-level event handler component
TykJS.TykEventHandlers.NewEventHandler = function() {
	TykJS.TykEventHandlers.EventHandlerComponentMeta.call(this)
}

// Set up object inheritance for events
TykJS.TykEventHandlers.NewEventHandler.prototype = Object.create(TykJS.TykEventHandlers.EventHandlerComponentMeta.prototype)
TykJS.TykEventHandlers.NewEventHandler.prototype.constructor = TykJS.TykEventHandlers.NewEventHandler

TykJS.TykEventHandlers.NewEventHandler.prototype.NewHandler = function(callback) {
	this.Handle = callback
};`
