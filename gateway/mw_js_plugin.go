package gateway

import (
	"bytes"
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
	"time"

	"github.com/robertkrimen/otto"
	_ "github.com/robertkrimen/otto/underscore"

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
	// This prevents the plugin from executing multiple times during internal routing
	// (e.g., VEM chain traversal, URL rewrites with tyk://self).
	// Pre-phase plugins run before auth and should execute on every request.
	// Similar to auth middleware behavior (see mw_auth_key.go:124).
	// Only applies to MCP proxies.
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
	expr := middlewareClassname + `.DoProcessRequest(` + string(requestAsJson) + `, ` + string(sessionAsJson) + `, ` + specAsJson + `);`
	logger.Debug("Running: ", middlewareClassname)

	runner := d.Spec.GetJSRunner()
	if runner == nil {
		logger.Error("JSVM isn't initialized, check your gateway settings")
		return errors.New("middleware error"), http.StatusInternalServerError
	}
	returnDataStr, err := runner.Run(expr)
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
			// Make sure we delete the header in case the header key was not canonical.
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
	// TODO: do we really need this conversion? note that we can't
	// make user.SessionState.MetaData a map[string]string, however.
	m2 := make(map[string]interface{}, len(m))
	for k, v := range m {
		m2[k] = v
	}
	return m2
}

// --- Utility functions during startup to ensure a sane VM is present for each API Def ----

type JSVM struct {
	Spec    *APISpec
	VM      *otto.Otto `json:"-"`
	Timeout time.Duration
	Log     *logrus.Entry  `json:"-"` // logger used by the JS code
	RawLog  *logrus.Logger `json:"-"` // logger used by `rawlog` func to avoid formatting
	Gw      *Gateway       `json:"-"`
}

const defaultJSVMTimeout = 5

// Init creates the JSVM with the core library and sets up a default
// timeout.
func (j *JSVM) Init(spec *APISpec, logger *logrus.Entry, gw *Gateway) {
	vm := otto.New()
	j.Gw = gw
	logger = logger.WithField("prefix", "jsvm")

	// Init TykJS namespace, constructors etc.
	if _, err := vm.Run(coreJS); err != nil {
		logger.WithError(err).Error("Could not load TykJS")
		return
	}

	// Load user's TykJS on top, if any
	if path := gw.GetConfig().TykJSPath; path != "" {
		f, err := os.Open(path)
		if err == nil {
			_, err = vm.Run(f)
			f.Close()

			if err != nil {
				logger.WithError(err).Error("Could not load user's TykJS")
			}
		}
	}

	j.VM = vm
	j.Spec = spec
	j.Log = logger
	j.RawLog = rawLog

	// Add environment API
	j.LoadTykJSApi()

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
}

// Ready implements JSRunner.
func (j *JSVM) Ready() bool {
	return j.VM != nil
}

// Run implements JSRunner. It copies the otto VM, executes the expression
// in a goroutine with timeout handling and panic recovery, and returns the
// stringified result.
func (j *JSVM) Run(expr string) (string, error) {
	if j.VM == nil {
		return "", errors.New("JSVM isn't enabled, check your gateway settings")
	}
	vm := j.VM.Copy()
	vm.Interrupt = make(chan func(), 1)
	ret := make(chan otto.Value, 1)
	errRet := make(chan error, 1)
	go func() {
		defer func() { _ = recover() }()
		returnRaw, err := vm.Run(expr)
		ret <- returnRaw
		errRet <- err
	}()
	t := time.NewTimer(j.Timeout)
	select {
	case returnRaw := <-ret:
		t.Stop()
		if err := <-errRet; err != nil {
			return "", err
		}
		s, err := returnRaw.ToString()
		if err != nil {
			return "", err
		}
		return s, nil
	case <-t.C:
		t.Stop()
		vm.Interrupt <- func() { panic("stop") }
		return "", fmt.Errorf("JS middleware timed out after %v", j.Timeout)
	}
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
		f, err := os.Open(mwPath)
		if err != nil {
			j.Log.WithError(err).Error("Failed to open JS middleware file")
			continue
		}
		if _, err := j.VM.Run(f); err != nil {
			j.Log.WithError(err).Error("Failed to load JS middleware")
		}
		f.Close()
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

func (j *JSVM) LoadTykJSApi() {
	h := &JSVMAPIHelper{Spec: j.Spec, Gw: j.Gw, Log: j.Log, RawLog: j.RawLog}

	toValue := func(v interface{}) otto.Value {
		val, err := j.VM.ToValue(v)
		if err != nil {
			h.Log.WithError(err).Error("Failed to convert value for JS")
			return otto.Value{}
		}
		return val
	}

	j.VM.Set("log", func(call otto.FunctionCall) otto.Value {
		h.LogMessage(call.Argument(0).String())
		return otto.Value{}
	})
	j.VM.Set("rawlog", func(call otto.FunctionCall) otto.Value {
		h.RawLogMessage(call.Argument(0).String())
		return otto.Value{}
	})
	j.VM.Set("b64dec", func(call otto.FunctionCall) otto.Value {
		out, err := h.B64Decode(call.Argument(0).String())
		if err != nil {
			return otto.Value{}
		}
		return toValue(out)
	})
	j.VM.Set("b64enc", func(call otto.FunctionCall) otto.Value {
		return toValue(h.B64Encode(call.Argument(0).String()))
	})
	j.VM.Set("rawb64dec", func(call otto.FunctionCall) otto.Value {
		out, err := h.RawB64Decode(call.Argument(0).String())
		if err != nil {
			return otto.Value{}
		}
		return toValue(out)
	})
	j.VM.Set("rawb64enc", func(call otto.FunctionCall) otto.Value {
		return toValue(h.RawB64Encode(call.Argument(0).String()))
	})
	j.VM.Set("TykMakeHttpRequest", func(call otto.FunctionCall) otto.Value {
		result, err := h.MakeHTTPRequest(call.Argument(0).String())
		if err != nil || result == "" {
			return otto.Value{}
		}
		return toValue(result)
	})
	j.VM.Set("TykGetKeyData", func(call otto.FunctionCall) otto.Value {
		return toValue(h.GetKeyData(call.Argument(0).String(), call.Argument(1).String()))
	})
	j.VM.Set("TykSetKeyData", func(call otto.FunctionCall) otto.Value {
		if err := h.SetKeyData(call.Argument(0).String(), call.Argument(1).String(), call.Argument(2).String()); err != nil {
			h.Log.WithError(err).Error("Failed to set key data from JS")
		}
		return otto.Value{}
	})
	j.VM.Set("TykBatchRequest", func(call otto.FunctionCall) otto.Value {
		result, err := h.BatchRequest(call.Argument(0).String())
		if err != nil {
			return otto.Value{}
		}
		return toValue(result)
	})

	j.VM.Run(`function TykJsResponse(response, session_meta) {
		return JSON.stringify({Response: response, SessionMeta: session_meta})
	}`)
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

TykJS.TykMiddleware.MiddlewareComponentMeta.prototype.ProcessResponse = function(response, request, session, config) {
	log("Process Response Not Implemented")
	return response
}

TykJS.TykMiddleware.MiddlewareComponentMeta.prototype.DoProcessResponse = function(response, request, session, config) {
	var processed_response = this.ProcessResponse(response, request, session, config)

	if (!processed_response) {
		log("Middleware didn't return response object!")
		return
	}

	return JSON.stringify(processed_response)
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

TykJS.TykMiddleware.NewMiddleware.prototype.NewProcessResponse = function(callback) {
	this.ProcessResponse = callback
}

TykJS.TykMiddleware.NewMiddleware.prototype.ReturnData = function(request, session) {
	return {Request: request, SessionMeta: session}
}

TykJS.TykMiddleware.NewMiddleware.prototype.ReturnResponseData = function(response, session) {
	return {Response: response, SessionMeta: session}
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
