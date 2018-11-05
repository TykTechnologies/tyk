package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
	"github.com/dop251/goja"
	_ "github.com/robertkrimen/otto/underscore"
)

type TykJSVM interface {
	Init(spec *APISpec, logger *logrus.Entry)
	LoadJSPaths(paths []string, prefix string)
	LoadTykJSApi()
	RunJSRequestDynamic(d *DynamicMiddleware, logger *logrus.Entry, requestAsJson string, sessionAsJson string, specAsJson string) (error, int, string)
	RunJSRequestVirtual(d *VirtualEndpoint, logger *logrus.Entry, vmeta *apidef.VirtualMeta, requestAsJson string, sessionAsJson string, specAsJson string) (error, int, string)
	Run(s string) (interface{}, error)
	GetLog() *logrus.Entry
	GetRawLog() *logrus.Logger
	GetTimeout() time.Duration
}

func InitJSVM() TykJSVM {

	switch config.Global().JSVM {
	case "goja":
		return &GojaJSVM{}
	default:
		return &OttoJSVM{}
	}
}

type GojaJSVM struct {
	Spec    *APISpec
	VM      *goja.Runtime
	Timeout time.Duration
	Log     *logrus.Entry  // logger used by the JS code
	RawLog  *logrus.Logger // logger used by `rawlog` func to avoid formatting
}

func (j *GojaJSVM) GetLog() *logrus.Entry {
	return j.Log
}

func (j *GojaJSVM) GetRawLog() *logrus.Logger {
	return j.RawLog
}

func (j *GojaJSVM) GetTimeout() time.Duration {
	return j.Timeout
}

// Init creates the JSVM with the core library and sets up a default
// timeout.
func (j *GojaJSVM) Init(spec *APISpec, logger *logrus.Entry) {
	vm := goja.New()
	logger = logger.WithField("prefix", "jsvm")

	// Init TykJS namespace, constructors etc.
	if _, err := vm.RunString(coreJS); err != nil {
		logger.WithError(err).Error("Could not load TykJS")
		return
	}

	// Load user's TykJS on top, if any
	if path := config.Global().TykJSPath; path != "" {
		f, err := ioutil.ReadFile(path)
		if err == nil {
			_, err = vm.RunString(string(f))

			if err != nil {
				logger.WithError(err).Error("Could not load user's TykJS")
			}
		}
	}

	j.VM = vm
	j.Spec = spec

	// Add environment API
	j.LoadTykJSApi()

	if jsvmTimeout := config.Global().JSVMTimeout; jsvmTimeout <= 0 {
		j.Timeout = time.Duration(defaultJSVMTimeout) * time.Second
		logger.Debugf("Default JSVM timeout used: %v", j.Timeout)
	} else {
		j.Timeout = time.Duration(jsvmTimeout) * time.Second
		logger.Debugf("Custom JSVM timeout: %v", j.Timeout)
	}

	j.Log = logger // use the global logger by default
	j.RawLog = rawLog
}

// LoadJSPaths will load JS classes and functionality in to the VM by file
func (j *GojaJSVM) LoadJSPaths(paths []string, prefix string) {
	for _, mwPath := range paths {
		if prefix != "" {
			mwPath = filepath.Join(prefix, mwPath)
		}
		j.Log.Info("Loading JS File: ", mwPath)
		f, err := ioutil.ReadFile(mwPath)
		if err != nil {
			j.Log.WithError(err).Error("Failed to open JS middleware file")
			continue
		}
		if _, err := j.VM.RunString(string(f)); err != nil {
			j.Log.WithError(err).Error("Failed to load JS middleware")
		}
	}
}

func (j *GojaJSVM) RunJSRequestDynamic(d *DynamicMiddleware, logger *logrus.Entry, requestAsJson string, sessionAsJson string, specAsJson string) (error, int, string) {
	middlewareClassname := d.MiddlewareClassName
	vm := j.VM
	interrupt := make(chan func(), 1)
	logger.Debug("Running: ", middlewareClassname)
	// buffered, leaving no chance of a goroutine leak since the
	// spawned goroutine will send 0 or 1 values.
	ret := make(chan goja.Value, 1)
	errRet := make(chan error, 1)
	go func() {
		defer func() {
			// the VM executes the panic func that gets it
			// to stop, so we must recover here to not crash
			// the whole Go program.
			recover()
		}()
		returnRaw, err := vm.RunString(middlewareClassname + `.DoProcessRequest(` + requestAsJson + `, ` + sessionAsJson + `, ` + specAsJson + `);`)
		ret <- returnRaw
		errRet <- err
	}()
	var returnRaw goja.Value
	t := time.NewTimer(d.Spec.JSVM.GetTimeout())
	select {
	case returnRaw = <-ret:
		if err := <-errRet; err != nil {
			logger.WithError(err).Error("Failed to run JS middleware")
			return nil, http.StatusOK, ""
		}
		t.Stop()
	case <-t.C:
		t.Stop()
		logger.Error("JS middleware timed out after ", d.Spec.JSVM.GetTimeout())
		interrupt <- func() {
			// only way to stop the VM is to send it a func
			// that panics.
			panic("stop")
		}
		return nil, http.StatusOK, ""
	}
	returnDataStr := returnRaw.String()
	return nil, -1, returnDataStr
}

func (j *GojaJSVM) RunJSRequestVirtual(d *VirtualEndpoint, logger *logrus.Entry, vmeta *apidef.VirtualMeta, requestAsJson string, sessionAsJson string, specAsJson string) (error, int, string) {

	interrupt := make(chan func(), 1)
	d.Logger().Debug("Running: ", vmeta.ResponseFunctionName)
	// buffered, leaving no chance of a goroutine leak since the
	// spawned goroutine will send 0 or 1 values.
	ret := make(chan goja.Value, 1)
	errRet := make(chan error, 1)
	go func() {
		defer func() {
			// the VM executes the panic func that gets it
			// to stop, so we must recover here to not crash
			// the whole Go program.
			recover()
		}()
		returnRaw, err := j.Run(vmeta.ResponseFunctionName + `(` + requestAsJson + `, ` + sessionAsJson + `, ` + specAsJson + `);`)
		ret <- returnRaw.(goja.Value)
		errRet <- err
	}()
	var returnRaw goja.Value
	t := time.NewTimer(j.GetTimeout())
	select {
	case returnRaw = <-ret:
		if err := <-errRet; err != nil {
			d.Logger().WithError(err).Error("Failed to run JS middleware")
			return nil, -1, ""
		}
		t.Stop()
	case <-t.C:
		t.Stop()
		d.Logger().Error("JS middleware timed out after ", j.GetTimeout())
		interrupt <- func() {
			// only way to stop the VM is to send it a func
			// that panics.
			panic("stop")
		}
		return nil, -1, ""
	}
	returnDataStr := returnRaw.String()
	return nil, -1, returnDataStr
}

func (j *GojaJSVM) LoadTykJSApi() {
	// Enable a log
	j.VM.Set("log", func(call goja.FunctionCall) goja.Value {
		j.Log.WithFields(logrus.Fields{
			"type": "log-msg",
		}).Info(call.Argument(0).String())
		return nil
	})
	j.VM.Set("rawlog", func(call goja.FunctionCall) goja.Value {
		j.RawLog.Print(call.Argument(0).String() + "\n")
		return nil
	})

	// these two needed for non-utf8 bodies
	j.VM.Set("b64dec", func(call goja.FunctionCall) goja.Value {
		in := call.Argument(0).String()
		out, err := base64.StdEncoding.DecodeString(in)

		// Fallback to RawStdEncoding:
		if err != nil {
			out, err = base64.RawStdEncoding.DecodeString(in)
			if err != nil {
				j.Log.WithError(err).Error("Failed to base64 decode")
				return nil
			}
		}
		returnVal := j.VM.ToValue(string(out))
		if returnVal == nil {
			j.Log.Error("Failed to base64 decode")
			return nil
		}
		return returnVal
	})
	j.VM.Set("b64enc", func(call goja.FunctionCall) goja.Value {
		in := []byte(call.Argument(0).String())
		out := base64.StdEncoding.EncodeToString(in)
		returnVal := j.VM.ToValue(out)
		if returnVal == nil {
			j.Log.Error("Failed to base64 encode")
			return nil
		}
		return returnVal
	})

	j.VM.Set("rawb64dec", func(call goja.FunctionCall) goja.Value {
		in := call.Argument(0).String()
		out, err := base64.RawStdEncoding.DecodeString(in)
		if err != nil {
			if err != nil {
				j.Log.WithError(err).Error("Failed to base64 decode")
				return nil
			}
		}
		returnVal := j.VM.ToValue(string(out))
		if returnVal == nil {
			j.Log.WithError(err).Error("Failed to base64 decode")
			return nil
		}
		return returnVal
	})
	j.VM.Set("rawb64enc", func(call goja.FunctionCall) goja.Value {
		in := []byte(call.Argument(0).String())
		out := base64.RawStdEncoding.EncodeToString(in)
		returnVal := j.VM.ToValue(out)
		if returnVal == nil {
			j.Log.Error("Failed to base64 encode")
			return nil
		}
		return returnVal
	})

	// Enable the creation of HTTP Requsts
	j.VM.Set("TykMakeHttpRequest", func(call goja.FunctionCall) goja.Value {
		jsonHRO := call.Argument(0).String()
		if jsonHRO == "undefined" {
			// Nope, return nothing
			return nil
		}
		hro := TykJSHttpRequest{}
		if err := json.Unmarshal([]byte(jsonHRO), &hro); err != nil {
			j.Log.WithError(err).Error("JSVM: Failed to deserialise HTTP Request object")
			return nil
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

		if config.Global().ProxySSLInsecureSkipVerify {
			tr.TLSClientConfig.InsecureSkipVerify = true
		}

		if j.Spec.Proxy.Transport.SSLInsecureSkipVerify {
			tr.TLSClientConfig.InsecureSkipVerify = true
		}

		tr.DialTLS = dialTLSPinnedCheck(j.Spec, tr.TLSClientConfig)

		tr.Proxy = proxyFromAPI(j.Spec)

		// using new Client each time should be ok, since we closing connection every time
		client := &http.Client{Transport: tr}
		resp, err := client.Do(r)
		if err != nil {
			j.Log.WithError(err).Error("Request failed")
			return nil
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
		returnVal := j.VM.ToValue(string(retAsStr))
		if returnVal == nil {
			j.Log.WithError(err).Error("Failed to encode return value")
			return nil
		}

		return returnVal
	})

	// Expose Setters and Getters in the REST API for a key:
	j.VM.Set("TykGetKeyData", func(call goja.FunctionCall) goja.Value {
		apiKey := call.Argument(0).String()
		apiId := call.Argument(1).String()

		obj, _ := handleGetDetail(apiKey, apiId, false)
		bs, _ := json.Marshal(obj)

		returnVal := j.VM.ToValue(string(bs))
		if returnVal == nil {
			j.Log.Error("Failed to encode return value")
			return nil
		}

		return returnVal
	})

	j.VM.Set("TykSetKeyData", func(call goja.FunctionCall) goja.Value {
		apiKey := call.Argument(0).String()
		encoddedSession := call.Argument(1).String()
		suppressReset := call.Argument(2).String()

		newSession := user.SessionState{}
		err := json.Unmarshal([]byte(encoddedSession), &newSession)
		if err != nil {
			j.Log.WithError(err).Error("Failed to decode the session data")
			return nil
		}

		doAddOrUpdate(apiKey, &newSession, suppressReset == "1")

		return nil
	})

	// Batch request method
	unsafeBatchHandler := BatchRequestHandler{}
	j.VM.Set("TykBatchRequest", func(call goja.FunctionCall) goja.Value {
		requestSet := call.Argument(0).String()
		j.Log.Debug("Batch input is: ", requestSet)

		bs, err := unsafeBatchHandler.ManualBatchRequest([]byte(requestSet))
		if err != nil {
			j.Log.WithError(err).Error("Batch request error")
			return nil
		}

		returnVal := j.VM.ToValue(string(bs))
		if err != nil {
			j.Log.WithError(err).Error("Failed to encode return value")
			return nil
		}

		return returnVal
	})

	j.VM.RunString(`function TykJsResponse(response, session_meta) {
		return JSON.stringify({Response: response, SessionMeta: session_meta})
	}`)
}

func (j *GojaJSVM) Run(s string) (interface{}, error) {

	return j.VM.RunString(s)
}

// wraps goja String() function to avoid using reflection in functions/tests when stringifying results of vm.Run() - so do it here where its safer to assume type
func (j *GojaJSVM) String(val interface{}) string {
	return val.(goja.Value).String()
}
