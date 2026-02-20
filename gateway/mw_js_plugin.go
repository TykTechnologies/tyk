package gateway

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/user"

	"github.com/sirupsen/logrus"
)

// Lets the user override and return a response from middleware
type ReturnOverrides struct {
	ResponseCode    int
	ResponseError   string
	ResponseBody    string
	ResponseHeaders map[string]string
	OverrideError   bool
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

func (mr *MiniRequestObject) ReconstructParams(r *http.Request) {
	updatedValues := r.URL.Query()

	for _, k := range mr.DeleteParams {
		updatedValues.Del(k)
	}

	for p, v := range mr.AddParams {
		updatedValues.Set(p, v)
	}

	for p, v := range mr.ExtendedParams {
		for _, val := range v {
			updatedValues.Add(p, val)
		}
	}

	if !reflect.DeepEqual(r.URL.Query(), updatedValues) {
		r.URL.RawQuery = updatedValues.Encode()
	}
}

type VMReturnObject struct {
	Request     MiniRequestObject
	SessionMeta map[string]string
	Session     user.SessionState
	AuthValue   string
}

// DynamicMiddleware is a generic middleware that will execute JS code before continuing
type DynamicMiddleware struct {
	*BaseMiddleware

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
	}

	if !spec.ConfigDataDisabled {
		m["config_data"] = spec.ConfigData
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
	// Skip post-phase JS plugins on self-looped requests (internal redirects).
	if d.Spec.IsMCP() && !d.Pre && httpctx.IsSelfLooping(r) {
		return nil, http.StatusOK
	}

	t1 := time.Now().UnixNano()
	logger := d.Logger()

	// Create the proxy object
	originalBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.WithError(err).Error("Failed to read request body")
		return nil, http.StatusOK
	}
	defer r.Body.Close()

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

	session := &user.SessionState{}

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
	middlewareClassname := d.MiddlewareClassName
	logger.Debug("Running: ", middlewareClassname)
	expr := middlewareClassname + `.DoProcessRequest(` + string(requestAsJson) + `, ` + string(sessionAsJson) + `, ` + specAsJson + `);`
	returnDataStr, err := d.Spec.JSVM.Run(expr)
	if err != nil {
		logger.WithError(err).Error("Failed to run JS middleware")
		return errors.New(http.StatusText(http.StatusInternalServerError)), http.StatusInternalServerError
	}

	// Decode the return object
	newRequestData := VMReturnObject{}
	if err := json.Unmarshal([]byte(returnDataStr), &newRequestData); err != nil {
		logger.WithError(err).Error("Failed to decode middleware request data on return from VM. Returned data: ", returnDataStr)
		return errors.New(http.StatusText(http.StatusInternalServerError)), http.StatusInternalServerError
	}

	// Reconstruct the request parts
	if newRequestData.Request.IgnoreBody {
		r.ContentLength = int64(len(originalBody))
		r.Body = ioutil.NopCloser(bytes.NewReader(originalBody))
	} else {
		r.ContentLength = int64(len(newRequestData.Request.Body))
		r.Body = ioutil.NopCloser(bytes.NewReader(newRequestData.Request.Body))
	}

	// make sure request's body can be re-read again
	nopCloseRequestBody(r)

	r.URL, err = url.Parse(newRequestData.Request.URL)
	if err != nil {
		return nil, http.StatusOK
	}

	ignoreCanonical := d.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey
	// Delete and set headers
	for _, dh := range newRequestData.Request.DeleteHeaders {
		r.Header.Del(dh)
		if ignoreCanonical {
			delete(r.Header, dh)
		}
	}
	for h, v := range newRequestData.Request.SetHeaders {
		setCustomHeader(r.Header, h, v, ignoreCanonical)
	}

	// Delete and set request parameters
	newRequestData.Request.ReconstructParams(r)

	// Save the session data (if modified)
	if !d.Pre && d.UseSession {
		newMeta := mapStrsToIfaces(newRequestData.SessionMeta)
		if session != nil && !reflect.DeepEqual(session.MetaData, newMeta) {
			session.MetaData = newMeta
			session.Touch()
		}
	}

	logger.Debug("JSVM middleware execution took: (ns) ", time.Now().UnixNano()-t1)

	if newRequestData.Request.ReturnOverrides.ResponseError != "" {
		newRequestData.Request.ReturnOverrides.ResponseBody = newRequestData.Request.ReturnOverrides.ResponseError
	}

	if newRequestData.Request.ReturnOverrides.ResponseCode >= http.StatusBadRequest && !newRequestData.Request.ReturnOverrides.OverrideError {

		for header, value := range newRequestData.Request.ReturnOverrides.ResponseHeaders {
			w.Header().Set(header, value)
		}

		return errors.New(newRequestData.Request.ReturnOverrides.ResponseBody), newRequestData.Request.ReturnOverrides.ResponseCode
	}

	if newRequestData.Request.ReturnOverrides.ResponseCode != 0 {
		responseObject := VMResponseObject{
			Response: ResponseObject{
				Body:    newRequestData.Request.ReturnOverrides.ResponseBody,
				Code:    newRequestData.Request.ReturnOverrides.ResponseCode,
				Headers: newRequestData.Request.ReturnOverrides.ResponseHeaders,
			},
		}

		d.Gw.forceResponse(w, r, &responseObject, d.Spec, session, d.Pre, logger)
		return nil, middleware.StatusRespond
	}

	if d.Auth {
		newRequestData.Session.KeyID = newRequestData.AuthValue

		switch d.Spec.BaseIdentityProvidedBy {
		case apidef.CustomAuth, apidef.UnsetAuth:
			ctxSetSession(r, &newRequestData.Session, true, d.Gw.GetConfig().HashKeys)
		}
	}

	return nil, http.StatusOK
}

func mapStrsToIfaces(m map[string]string) map[string]interface{} {
	m2 := make(map[string]interface{}, len(m))
	for k, v := range m {
		m2[k] = v
	}
	return m2
}

// --- Utility functions during startup to ensure a sane VM is present for each API Def ----

type JSVM struct {
	Spec    *APISpec
	Timeout time.Duration
	Log     *logrus.Entry  `json:"-"` // logger used by the JS code
	RawLog  *logrus.Logger `json:"-"` // logger used by `rawlog` func to avoid formatting
	Gw      *Gateway       `json:"-"`

	vm *goja.Runtime  // single pre-initialized runtime, guarded by mu
	mu *sync.Mutex
}

// Initialized reports whether the JSVM has been set up.
func (j *JSVM) Initialized() bool {
	return j.vm != nil
}

// Run executes a JS expression on the VM with timeout handling.
// Access is serialized via a mutex; timeout uses goja's Interrupt (goroutine-safe).
func (j *JSVM) Run(expr string) (string, error) {
	if j.vm == nil {
		return "", errors.New("JSVM isn't enabled, check your gateway settings")
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	timer := time.AfterFunc(j.Timeout, func() {
		j.vm.Interrupt("timeout")
	})
	defer timer.Stop()

	returnRaw, err := j.vm.RunString(expr)
	if err != nil {
		// Clear the interrupt flag so the VM is usable for the next call.
		j.vm.ClearInterrupt()
		if _, ok := err.(*goja.InterruptedError); ok {
			return "", fmt.Errorf("JS middleware timed out after %v", j.Timeout)
		}
		return "", err
	}

	return returnRaw.String(), nil
}

// LoadScript runs a JS source string on the VM (used during init/load, not per-request).
func (j *JSVM) LoadScript(src string) error {
	if j.vm == nil {
		return errors.New("JSVM not initialized")
	}
	_, err := j.vm.RunString(src)
	return err
}

const defaultJSVMTimeout = 5

// Init creates the JSVM with the core library and sets up a default
// timeout.
func (j *JSVM) Init(spec *APISpec, logger *logrus.Entry, gw *Gateway) {
	j.Gw = gw
	j.mu = &sync.Mutex{}
	logger = logger.WithField("prefix", "jsvm")

	vm := goja.New()

	// Register Go API functions first so JS init code can call log(), b64dec(), etc.
	j.Log = logger
	j.RawLog = rawLog
	j.Spec = spec
	j.vm = vm
	j.registerAPI(vm)

	// Init TykJS namespace, constructors etc.
	if _, err := vm.RunString(coreJS); err != nil {
		logger.WithError(err).Error("Could not load TykJS")
		j.vm = nil
		return
	}

	// Load user's TykJS on top, if any
	if path := gw.GetConfig().TykJSPath; path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			if _, err := vm.RunString(string(data)); err != nil {
				logger.WithError(err).Error("Could not load user's TykJS")
			}
		}
	}

	// Define the TykJsResponse helper
	vm.RunString(`function TykJsResponse(response, session_meta) {
		return JSON.stringify({Response: response, SessionMeta: session_meta})
	}`)

	if jsvmTimeout := gw.GetConfig().JSVMTimeout; jsvmTimeout <= 0 {
		j.Timeout = time.Duration(defaultJSVMTimeout) * time.Second
		logger.Debugf("Default JSVM timeout used: %v", j.Timeout)
	} else {
		j.Timeout = time.Duration(jsvmTimeout) * time.Second
		logger.Debugf("Custom JSVM timeout: %v", j.Timeout)
	}
}

func (j *JSVM) DeInit() {
	j.Spec = nil
	j.Log = nil
	j.RawLog = nil
	j.Gw = nil
	j.vm = nil
}

// LoadJSPaths will load JS classes and functionality in to the VM by file
func (j *JSVM) LoadJSPaths(paths []string, prefix string) {
	for _, mwPath := range paths {
		if prefix != "" {
			mwPath = filepath.Join(prefix, mwPath)
		}
		extension := filepath.Ext(mwPath)
		if !strings.Contains(extension, ".js") {
			j.Log.Errorf("Unsupported extension '%s' (%s)", extension, mwPath)
			continue
		}
		j.Log.Info("Loading JS File: ", mwPath)
		data, err := os.ReadFile(mwPath)
		if err != nil {
			j.Log.WithError(err).Error("Failed to open JS middleware file")
			continue
		}
		if _, err := j.vm.RunString(string(data)); err != nil {
			j.Log.WithError(err).Error("Failed to load JS middleware")
		}
	}
}

type TykJSHttpRequest struct {
	Method   string
	Body     string
	Headers  map[string]string
	Domain   string
	Resource string
	FormData map[string]string
}

type TykJSHttpResponse struct {
	Code    int
	Body    string
	Headers map[string][]string

	// Make this compatible with BatchReplyUnit
	CodeComp    int                 `json:"code"`
	BodyComp    string              `json:"body"`
	HeadersComp map[string][]string `json:"headers"`
}

func (j *JSVM) registerAPI(vm *goja.Runtime) {
	// Enable a log
	vm.Set("log", func(call goja.FunctionCall) goja.Value {
		j.Log.WithFields(logrus.Fields{
			"type": "log-msg",
		}).Info(call.Argument(0).String())
		return goja.Undefined()
	})
	vm.Set("rawlog", func(call goja.FunctionCall) goja.Value {
		j.RawLog.Print(call.Argument(0).String() + "\n")
		return goja.Undefined()
	})

	// these two needed for non-utf8 bodies
	vm.Set("b64dec", func(call goja.FunctionCall) goja.Value {
		in := call.Argument(0).String()
		out, err := base64.StdEncoding.DecodeString(in)

		// Fallback to RawStdEncoding:
		if err != nil {
			out, err = base64.RawStdEncoding.DecodeString(in)
			if err != nil {
				j.Log.WithError(err).Error("Failed to base64 decode")
				return goja.Undefined()
			}
		}
		return vm.ToValue(string(out))
	})
	vm.Set("b64enc", func(call goja.FunctionCall) goja.Value {
		in := []byte(call.Argument(0).String())
		out := base64.StdEncoding.EncodeToString(in)
		return vm.ToValue(out)
	})

	vm.Set("rawb64dec", func(call goja.FunctionCall) goja.Value {
		in := call.Argument(0).String()
		out, err := base64.RawStdEncoding.DecodeString(in)
		if err != nil {
			j.Log.WithError(err).Error("Failed to base64 decode")
			return goja.Undefined()
		}
		return vm.ToValue(string(out))
	})
	vm.Set("rawb64enc", func(call goja.FunctionCall) goja.Value {
		in := []byte(call.Argument(0).String())
		out := base64.RawStdEncoding.EncodeToString(in)
		return vm.ToValue(out)
	})
	ignoreCanonical := j.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey
	// Enable the creation of HTTP Requests
	vm.Set("TykMakeHttpRequest", func(call goja.FunctionCall) goja.Value {
		jsonHRO := call.Argument(0).String()
		if jsonHRO == "undefined" {
			return goja.Undefined()
		}
		hro := TykJSHttpRequest{}
		if err := json.Unmarshal([]byte(jsonHRO), &hro); err != nil {
			j.Log.WithError(err).Error("JSVM: Failed to deserialise HTTP Request object")
			return goja.Undefined()
		}

		// Make the request
		domain := hro.Domain
		data := url.Values{}
		for k, v := range hro.FormData {
			data.Set(k, v)
		}

		u, _ := url.ParseRequestURI(domain + hro.Resource)
		urlStr := u.String()

		var d string
		if hro.Body != "" {
			d = hro.Body
		} else if len(hro.FormData) > 0 {
			d = data.Encode()
		}

		r, _ := http.NewRequest(hro.Method, urlStr, nil)

		if d != "" {
			r, _ = http.NewRequest(hro.Method, urlStr, strings.NewReader(d))
		}

		for k, v := range hro.Headers {
			setCustomHeader(r.Header, k, v, ignoreCanonical)
		}
		r.Close = true

		maxSSLVersion := j.Gw.GetConfig().ProxySSLMaxVersion
		if j.Spec.Proxy.Transport.SSLMaxVersion > 0 {
			maxSSLVersion = j.Spec.Proxy.Transport.SSLMaxVersion
		}

		tr := &http.Transport{TLSClientConfig: &tls.Config{
			MaxVersion: maxSSLVersion,
		}}

		if cert := j.Gw.getUpstreamCertificate(r.Host, j.Spec); cert != nil {
			tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
		}

		if j.Gw.GetConfig().ProxySSLInsecureSkipVerify {
			tr.TLSClientConfig.InsecureSkipVerify = true
		}

		if j.Spec.Proxy.Transport.SSLInsecureSkipVerify {
			tr.TLSClientConfig.InsecureSkipVerify = true
		}

		tr.DialTLS = j.Gw.customDialTLSCheck(j.Spec, tr.TLSClientConfig)

		tr.Proxy = proxyFromAPI(j.Spec)

		client := &http.Client{Transport: tr}
		resp, err := client.Do(r)
		if err != nil {
			j.Log.WithError(err).Error("Request failed")
			return goja.Undefined()
		}

		body, _ := ioutil.ReadAll(resp.Body)
		bodyStr := string(body)
		tykResp := TykJSHttpResponse{
			Code:        resp.StatusCode,
			Body:        bodyStr,
			Headers:     resp.Header,
			CodeComp:    resp.StatusCode,
			BodyComp:    bodyStr,
			HeadersComp: resp.Header,
		}

		retAsStr, _ := json.Marshal(tykResp)
		return vm.ToValue(string(retAsStr))
	})

	// Expose Setters and Getters in the REST API for a key:
	vm.Set("TykGetKeyData", func(call goja.FunctionCall) goja.Value {
		apiKey := call.Argument(0).String()
		apiId := call.Argument(1).String()

		obj, _ := j.Gw.handleGetDetail(apiKey, apiId, "", false)
		bs, _ := json.Marshal(obj)

		return vm.ToValue(string(bs))
	})

	vm.Set("TykSetKeyData", func(call goja.FunctionCall) goja.Value {
		apiKey := call.Argument(0).String()
		encoddedSession := call.Argument(1).String()
		suppressReset := call.Argument(2).String()

		newSession := user.SessionState{}
		err := json.Unmarshal([]byte(encoddedSession), &newSession)
		if err != nil {
			j.Log.WithError(err).Error("Failed to decode the sesison data")
			return goja.Undefined()
		}

		j.Gw.doAddOrUpdate(apiKey, &newSession, suppressReset == "1", false)
		return goja.Undefined()
	})

	// Batch request method
	unsafeBatchHandler := BatchRequestHandler{Gw: j.Gw}
	vm.Set("TykBatchRequest", func(call goja.FunctionCall) goja.Value {
		requestSet := call.Argument(0).String()
		j.Log.Debug("Batch input is: ", requestSet)
		bs, err := unsafeBatchHandler.ManualBatchRequest([]byte(requestSet))
		if err != nil {
			j.Log.WithError(err).Error("Batch request error")
			return goja.Undefined()
		}

		return vm.ToValue(string(bs))
	})
}

// Response processing support
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

// Response processing
TykJS.TykMiddleware.MiddlewareComponentMeta.prototype.ProcessResponse = function(response, session, config) {
	log("Process Response Not Implemented")
	return response
}

TykJS.TykMiddleware.MiddlewareComponentMeta.prototype.DoProcessResponse = function(response, session, config) {
	response.Body = b64dec(response.Body)
	var processed_response = this.ProcessResponse(response, session, config)

	if (!processed_response) {
		log("Middleware didn't return response object!")
		return
	}

	processed_response.Response.Body = b64enc(processed_response.Response.Body)

	return JSON.stringify(processed_response)
}

TykJS.TykMiddleware.NewMiddleware.prototype.NewProcessResponse = function(callback) {
	this.ProcessResponse = callback
}

TykJS.TykMiddleware.NewMiddleware.prototype.ReturnResponseData = function(response, session_meta) {
	return {Response: response, SessionMeta: session_meta}
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
