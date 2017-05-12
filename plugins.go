package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/gorilla/context"
	"github.com/mitchellh/mapstructure"
	"github.com/robertkrimen/otto"
	_ "github.com/robertkrimen/otto/underscore"

	"github.com/Sirupsen/logrus"
)

// Lets the user override and return a response from middleware
type ReturnOverrides struct {
	ResponseCode  int
	ResponseError string
}

// MiniRequestObject is marshalled to JSON string and passed into JSON middleware
type MiniRequestObject struct {
	Headers         map[string][]string
	SetHeaders      map[string]string
	DeleteHeaders   []string
	Body            string
	URL             string
	Params          map[string][]string
	AddParams       map[string]string
	ExtendedParams  map[string][]string
	DeleteParams    []string
	ReturnOverrides ReturnOverrides
	IgnoreBody      bool
}

type VMReturnObject struct {
	Request     MiniRequestObject
	SessionMeta map[string]string
	Session     SessionState
	AuthValue   string
}

// DynamicMiddleware is a generic middleware that will execute JS code before continuing
type DynamicMiddleware struct {
	*TykMiddleware
	MiddlewareClassName string
	Pre                 bool
	UseSession          bool
	Auth                bool
}

type DynamicMiddlewareConfig struct {
	ConfigData map[string]string `mapstructure:"config_data" bson:"config_data" json:"config_data"`
}

func (d *DynamicMiddleware) GetName() string {
	return "DynamicMiddleware"
}

// New lets you do any initialisations for the object can be done here
func (d *DynamicMiddleware) New() {}

func (d *DynamicMiddleware) IsEnabledForSpec() bool { return true }

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (d *DynamicMiddleware) GetConfig() (interface{}, error) {
	var moduleConfig DynamicMiddlewareConfig

	err := mapstructure.Decode(d.TykMiddleware.Spec.APIDefinition.RawData, &moduleConfig)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error(err)
		return nil, err
	}

	return moduleConfig, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (d *DynamicMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

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
		SetHeaders:     make(map[string]string),
		DeleteHeaders:  make([]string, 0),
		Body:           string(originalBody),
		URL:            r.URL.Path,
		Params:         r.URL.Query(),
		AddParams:      make(map[string]string),
		ExtendedParams: make(map[string][]string),
		DeleteParams:   make([]string, 0),
		IgnoreBody:     false,
	}

	asJsonRequestObj, err := json.Marshal(requestData)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error("Failed to encode request object for dynamic middleware: ", err)
		return nil, 200
	}

	sessionState := SessionState{}
	authHeaderValue := ""

	// Encode the session object (if not a pre-process)
	if !d.Pre {
		if d.UseSession {
			sessionState = context.Get(r, SessionData).(SessionState)
			authHeaderValue = context.Get(r, AuthHeaderValue).(string)
		}
	}

	sessionAsJsonObj, err := json.Marshal(sessionState)
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
	ret := make(chan otto.Value)
	go func() {
		defer func() {
			// the VM executes the panic func that gets it
			// to stop, so we must recover here to not crash
			// the whole Go program.
			recover()
			// send a dummy value to the ret channel to
			// signal that we died, since a panic will mean
			// the regular send won't happen.
			ret <- otto.Value{}
		}()
		returnRaw, _ := vm.Run(middlewareClassname + `.DoProcessRequest(` + string(asJsonRequestObj) + `, ` + string(sessionAsJsonObj) + `);`)
		ret <- returnRaw
	}()
	var returnRaw otto.Value
	t := time.NewTimer(d.Spec.JSVM.Timeout)
	select {
	case returnRaw = <-ret:
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
		// wait for the vm goroutine to die, ensuring that we
		// have no goroutine leak.
		<-ret
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
		r.Body = ioutil.NopCloser(bytes.NewBuffer(originalBody))
	} else {
		r.ContentLength = int64(len(newRequestData.Request.Body))
		r.Body = ioutil.NopCloser(bytes.NewBufferString(newRequestData.Request.Body))
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
		sessionState.MetaData = mapStrsToIfaces(newRequestData.SessionMeta)
		d.Spec.SessionManager.UpdateSession(authHeaderValue, sessionState, getLifetime(d.Spec, &sessionState))
	}

	log.WithFields(logrus.Fields{
		"prefix": "jsvm",
	}).Debug("JSVM middleware execution took: (ns) ", time.Now().UnixNano()-t1)

	if newRequestData.Request.ReturnOverrides.ResponseCode != 0 {
		return errors.New(newRequestData.Request.ReturnOverrides.ResponseError), newRequestData.Request.ReturnOverrides.ResponseCode
	}

	if d.Auth {
		context.Set(r, SessionData, newRequestData.Session)
		context.Set(r, AuthHeaderValue, newRequestData.AuthValue)
	}

	return nil, 200
}

func mapStrsToIfaces(m map[string]string) map[string]interface{} {
	// TODO: do we really need this conversion? perhaps make
	// SessionState.MetaData a map[string]string?
	m2 := make(map[string]interface{}, len(m))
	for k, v := range m {
		m2[k] = v
	}
	return m2
}

// --- Utility functions during startup to ensure a sane VM is present for each API Def ----

type JSVM struct {
	VM      *otto.Otto
	Timeout time.Duration
}

// Init creates the JSVM with the core library (tyk.js) and sets up a
// default timeout.
func (j *JSVM) Init() {
	vm := otto.New()

	// Init TykJS namespace, constructors etc.
	jscore, _ := ioutil.ReadFile(config.TykJSPath)
	vm.Run(jscore)

	j.VM = vm

	// Add environment API
	j.LoadTykJSApi()

	j.Timeout = 5 * time.Second
}

// LoadJSPaths will load JS classes and functionality in to the VM by file
func (j *JSVM) LoadJSPaths(paths []string, pathPrefix string) {
	for _, mwPath := range paths {
		if pathPrefix != "" {
			mwPath = filepath.Join(tykBundlePath, pathPrefix, mwPath)
		}
		js, err := ioutil.ReadFile(mwPath)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("Failed to load Middleware JS: ", err)
		} else {
			// No error, load the JS into the VM
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Info("Loading JS File: ", mwPath)
			j.VM.Run(js)
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
}

func (j *JSVM) LoadTykJSApi() {
	// Enable a log
	j.VM.Set("log", func(call otto.FunctionCall) otto.Value {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm-logmsg",
			"type":   "log-msg",
		}).Info(call.Argument(0).String())
		return otto.Value{}
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

		client := &http.Client{}

		var d string
		if hro.Body != "" {
			d = hro.Body
		} else if len(hro.FormData) > 0 {
			d = data.Encode()
		}

		r, _ := http.NewRequest(hro.Method, urlStr, nil)

		if d != "" {
			r, _ = http.NewRequest(hro.Method, urlStr, bytes.NewBufferString(d))
		}

		for k, v := range hro.Headers {
			r.Header.Add(k, v)
		}
		r.Close = true
		resp, err := client.Do(r)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("[JSVM]: Request failed: ", err)
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
			}).Error("[JSVM]: Failed to encode return value: ", err)
			return otto.Value{}
		}

		return returnVal
	})

	// Expose Setters and Getters in the REST API for a key:

	j.VM.Set("TykGetKeyData", func(call otto.FunctionCall) otto.Value {
		apiKey := call.Argument(0).String()
		apiId := call.Argument(1).String()

		byteArray, _ := handleGetDetail(apiKey, apiId)

		returnVal, err := j.VM.ToValue(string(byteArray))
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("[JSVM]: Failed to encode return value: ", err)
			return otto.Value{}
		}

		return returnVal
	})

	j.VM.Set("TykSetKeyData", func(call otto.FunctionCall) otto.Value {
		apiKey := call.Argument(0).String()
		encoddedSession := call.Argument(1).String()
		suppressReset := call.Argument(2).String()

		newSession := SessionState{}
		err := json.Unmarshal([]byte(encoddedSession), &newSession)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("[JSVM]: Failed to decode the sesison data")
			return otto.Value{}
		}

		doAddOrUpdate(apiKey, newSession, suppressReset == "1")

		return otto.Value{}
	})

	// Batch request method
	unsafeBatchHandler := BatchRequestHandler{}
	j.VM.Set("TykBatchRequest", func(call otto.FunctionCall) otto.Value {
		requestSet := call.Argument(0).String()
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Debug("Batch input is: ", requestSet)

		byteArray := unsafeBatchHandler.ManualBatchRequest([]byte(requestSet))

		returnVal, err := j.VM.ToValue(string(byteArray))
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("[JSVM]: Failed to encode return value: ", err)
			return otto.Value{}
		}

		return returnVal
	})

	tykReturnFunc := `
	function TykJsResponse(response, session_meta) {
		return JSON.stringify({Response: response, SessionMeta: session_meta})
	};`

	j.VM.Run(tykReturnFunc)

}
