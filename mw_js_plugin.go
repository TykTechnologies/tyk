package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/robertkrimen/otto"
	_ "github.com/robertkrimen/otto/underscore"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"

	"github.com/Sirupsen/logrus"
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

	// Createthe proxy object
	defer r.Body.Close()
	originalBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error("Failed to read request body! ", err)
		return nil, 200
	}

	requestData := MiniRequestObject{
		Headers:        r.Header,
		SetHeaders:     map[string]string{},
		DeleteHeaders:  []string{},
		Body:           originalBody,
		URL:            r.URL.Path,
		Params:         r.URL.Query(),
		AddParams:      map[string]string{},
		ExtendedParams: map[string][]string{},
		DeleteParams:   []string{},
		Method:         r.Method,
		RequestURI:     r.RequestURI,
	}

	requestAsJson, err := json.Marshal(requestData)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error("Failed to encode request object for dynamic middleware: ", err)
		return nil, 200
	}

	specAsJson := specToJson(d.Spec)

	session := new(user.SessionState)
	token := ctxGetAuthToken(r)

	// Encode the session object (if not a pre-process)
	if !d.Pre && d.UseSession {
		session = ctxGetSession(r)
	}

	sessionAsJson, err := json.Marshal(session)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error("Failed to encode session for VM: ", err)
		return nil, 200
	}

	// Run the middleware
	middlewareClassname := d.MiddlewareClassName
	vm := d.Spec.JSVM.VM.Copy()
	vm.Interrupt = make(chan func(), 1)
	log.WithFields(logrus.Fields{
		"prefix": "jsvm",
	}).Debug("Running: ", middlewareClassname)
	// buffered, leaving no chance of a goroutine leak since the
	// spawned goroutine will send 0 or 1 values.
	ret := make(chan otto.Value, 1)
	errRet := make(chan error, 1)
	go func() {
		defer func() {
			// the VM executes the panic func that gets it
			// to stop, so we must recover here to not crash
			// the whole Go program.
			recover()
		}()
		returnRaw, err := vm.Run(middlewareClassname + `.DoProcessRequest(` + string(requestAsJson) + `, ` + string(sessionAsJson) + `, ` + specAsJson + `);`)
		ret <- returnRaw
		errRet <- err
	}()
	var returnRaw otto.Value
	t := time.NewTimer(d.Spec.JSVM.Timeout)
	select {
	case returnRaw = <-ret:
		if err := <-errRet; err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("Failed to run JS middleware: ", err)
			return nil, 200
		}
		t.Stop()
	case <-t.C:
		t.Stop()
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error("JS middleware timed out after ", d.Spec.JSVM.Timeout)
		vm.Interrupt <- func() {
			// only way to stop the VM is to send it a func
			// that panics.
			panic("stop")
		}
		return nil, 200
	}
	returnDataStr, _ := returnRaw.ToString()

	// Decode the return object
	newRequestData := VMReturnObject{}
	if err := json.Unmarshal([]byte(returnDataStr), &newRequestData); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error("Failed to decode middleware request data on return from VM: ", err)
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Debug(returnDataStr)
		return nil, 200
	}

	// Reconstruct the request parts
	if newRequestData.Request.IgnoreBody {
		r.ContentLength = int64(len(originalBody))
		r.Body = ioutil.NopCloser(bytes.NewReader(originalBody))
	} else {
		r.ContentLength = int64(len(newRequestData.Request.Body))
		r.Body = ioutil.NopCloser(bytes.NewReader(newRequestData.Request.Body))
	}

	r.URL.Path = newRequestData.Request.URL

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
	if !d.Pre && d.UseSession && len(newRequestData.SessionMeta) > 0 {
		session.MetaData = mapStrsToIfaces(newRequestData.SessionMeta)
		d.Spec.SessionManager.UpdateSession(token, session, session.Lifetime(d.Spec.SessionLifetime))
	}

	log.WithFields(logrus.Fields{
		"prefix": "jsvm",
	}).Debug("JSVM middleware execution took: (ns) ", time.Now().UnixNano()-t1)

	if newRequestData.Request.ReturnOverrides.ResponseCode >= 400 {
		return errors.New(newRequestData.Request.ReturnOverrides.ResponseError), newRequestData.Request.ReturnOverrides.ResponseCode
	}

	if newRequestData.Request.ReturnOverrides.ResponseCode != 0 && newRequestData.Request.ReturnOverrides.ResponseCode < 300 {

		responseObject := VMResponseObject{
			Response: ResponseObject{
				Body:    newRequestData.Request.ReturnOverrides.ResponseError,
				Code:    newRequestData.Request.ReturnOverrides.ResponseCode,
				Headers: newRequestData.Request.ReturnOverrides.ResponseHeaders,
			},
		}

		forceResponse(w, r, &responseObject, d.Spec, session, d.Pre)
		return nil, mwStatusRespond
	}

	if d.Auth {
		ctxSetSession(r, &newRequestData.Session)
		ctxSetAuthToken(r, newRequestData.AuthValue)
	}

	return nil, 200
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
	VM      *otto.Otto
	Timeout time.Duration
	Log     *logrus.Logger // logger used by the JS code
	RawLog  *logrus.Logger // logger used by `rawlog` func to avoid formatting
}

// Init creates the JSVM with the core library and sets up a default
// timeout.
func (j *JSVM) Init(spec *APISpec) {
	vm := otto.New()

	// Init TykJS namespace, constructors etc.
	if _, err := vm.Run(coreJS); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error("Could not load TykJS: ", err)
		return
	}

	// Load user's TykJS on top, if any
	if path := config.Global.TykJSPath; path != "" {
		f, err := os.Open(path)
		if err == nil {
			_, err = vm.Run(f)
			f.Close()
		}
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("Could not load user's TykJS: ", err)
			return
		}
	}

	j.VM = vm
	j.Spec = spec

	// Add environment API
	j.LoadTykJSApi()

	j.Timeout = 5 * time.Second
	j.Log = log // use the global logger by default
	j.RawLog = rawLog
}

// LoadJSPaths will load JS classes and functionality in to the VM by file
func (j *JSVM) LoadJSPaths(paths []string, pathPrefix string) {
	tykBundlePath := filepath.Join(config.Global.MiddlewarePath, "bundles")
	for _, mwPath := range paths {
		if pathPrefix != "" {
			mwPath = filepath.Join(tykBundlePath, pathPrefix, mwPath)
		}
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Info("Loading JS File: ", mwPath)
		f, err := os.Open(mwPath)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("Failed to open JS middleware file: ", err)
			continue
		}
		if _, err := j.VM.Run(f); err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("Failed to load JS middleware: ", err)
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
}

func (j *JSVM) LoadTykJSApi() {
	// Enable a log
	j.VM.Set("log", func(call otto.FunctionCall) otto.Value {
		j.Log.WithFields(logrus.Fields{
			"prefix": "jsvm-logmsg",
			"type":   "log-msg",
		}).Info(call.Argument(0).String())
		return otto.Value{}
	})
	j.VM.Set("rawlog", func(call otto.FunctionCall) otto.Value {
		j.RawLog.Print(call.Argument(0).String() + "\n")
		return otto.Value{}
	})

	// these two needed for non-utf8 bodies
	j.VM.Set("b64dec", func(call otto.FunctionCall) otto.Value {
		in := call.Argument(0).String()
		out, err := base64.StdEncoding.DecodeString(in)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("Failed to base64 decode: ", err)
			return otto.Value{}
		}
		returnVal, err := j.VM.ToValue(string(out))
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("Failed to base64 decode: ", err)
			return otto.Value{}
		}
		return returnVal
	})
	j.VM.Set("b64enc", func(call otto.FunctionCall) otto.Value {
		in := []byte(call.Argument(0).String())
		out := base64.StdEncoding.EncodeToString(in)
		returnVal, err := j.VM.ToValue(out)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("Failed to base64 encode: ", err)
			return otto.Value{}
		}
		return returnVal
	})

	// Enable the creation of HTTP Requsts
	j.VM.Set("TykMakeHttpRequest", func(call otto.FunctionCall) otto.Value {

		jsonHRO := call.Argument(0).String()
		if jsonHRO == "undefined" {
			// Nope, return nothing
			return otto.Value{}
		}
		hro := TykJSHttpRequest{}
		if err := json.Unmarshal([]byte(jsonHRO), &hro); err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("JSVM: Failed to deserialise HTTP Request object")
			return otto.Value{}
		}

		// Make the request
		domain := hro.Domain
		data := url.Values{}
		for k, v := range hro.FormData {
			data.Set(k, v)
		}

		u, _ := url.ParseRequestURI(domain)
		u.Path = hro.Resource
		urlStr := u.String() // "https://api.com/user/"

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
			r.Header.Set(k, v)
		}
		r.Close = true

		tr := &http.Transport{TLSClientConfig: &tls.Config{}}
		if cert := getUpstreamCertificate(r.Host, j.Spec); cert != nil {
			tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
		}

		if config.Global.ProxySSLInsecureSkipVerify {
			tr.TLSClientConfig.InsecureSkipVerify = true
		}

		// using new Client each time should be ok, since we closing connection every time
		client := &http.Client{Transport: tr}
		resp, err := client.Do(r)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("Request failed: ", err)
			return otto.Value{}
		}

		body, _ := ioutil.ReadAll(resp.Body)
		tykResp := TykJSHttpResponse{
			Code:    resp.StatusCode,
			Body:    string(body),
			Headers: resp.Header,
		}

		retAsStr, _ := json.Marshal(tykResp)
		returnVal, err := j.VM.ToValue(string(retAsStr))
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("Failed to encode return value: ", err)
			return otto.Value{}
		}

		return returnVal
	})

	// Expose Setters and Getters in the REST API for a key:
	j.VM.Set("TykGetKeyData", func(call otto.FunctionCall) otto.Value {
		apiKey := call.Argument(0).String()
		apiId := call.Argument(1).String()

		obj, _ := handleGetDetail(apiKey, apiId)
		bs, _ := json.Marshal(obj)

		returnVal, err := j.VM.ToValue(string(bs))
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("Failed to encode return value: ", err)
			return otto.Value{}
		}

		return returnVal
	})

	j.VM.Set("TykSetKeyData", func(call otto.FunctionCall) otto.Value {
		apiKey := call.Argument(0).String()
		encoddedSession := call.Argument(1).String()
		suppressReset := call.Argument(2).String()

		newSession := user.SessionState{}
		err := json.Unmarshal([]byte(encoddedSession), &newSession)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("Failed to decode the sesison data")
			return otto.Value{}
		}

		doAddOrUpdate(apiKey, &newSession, suppressReset == "1")

		return otto.Value{}
	})

	// Batch request method
	unsafeBatchHandler := BatchRequestHandler{}
	j.VM.Set("TykBatchRequest", func(call otto.FunctionCall) otto.Value {
		requestSet := call.Argument(0).String()
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Debug("Batch input is: ", requestSet)

		bs, err := unsafeBatchHandler.ManualBatchRequest([]byte(requestSet))
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error(err)
			return otto.Value{}
		}

		returnVal, err := j.VM.ToValue(string(bs))
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("Failed to encode return value: ", err)
			return otto.Value{}
		}

		return returnVal
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
