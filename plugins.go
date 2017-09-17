package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/robertkrimen/otto"
	_ "github.com/robertkrimen/otto/underscore"

	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/tyk/jsvm"
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
}

type VMReturnObject struct {
	Request     MiniRequestObject
	SessionMeta map[string]string
	Session     SessionState
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

func jsonConfigData(spec *APISpec) string {
	m := map[string]interface{}{
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
	}

	asJsonRequestObj, err := json.Marshal(requestData)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error("Failed to encode request object for dynamic middleware: ", err)
		return nil, 200
	}

	confData := jsonConfigData(d.Spec)

	session := new(SessionState)
	token := ctxGetAuthToken(r)

	// Encode the session object (if not a pre-process)
	if !d.Pre && d.UseSession {
		session = ctxGetSession(r)
	}

	sessionAsJsonObj, err := json.Marshal(session)
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
		returnRaw, err := vm.Run(middlewareClassname + `.DoProcessRequest(` + string(asJsonRequestObj) + `, ` + string(sessionAsJsonObj) + `, ` + confData + `);`)
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
		d.Spec.SessionManager.UpdateSession(token, session, getLifetime(d.Spec, session))
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
	// make SessionState.MetaData a map[string]string, however.
	m2 := make(map[string]interface{}, len(m))
	for k, v := range m {
		m2[k] = v
	}
	return m2
}

type JSVM = jsvm.JSVM
type TykJSHttpRequest = jsvm.TykJSHttpRequest
type TykJSHttpResponse = jsvm.TykJSHttpResponse