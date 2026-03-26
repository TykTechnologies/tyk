package gateway

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dop251/goja"

	"github.com/TykTechnologies/tyk/user"

	"github.com/sirupsen/logrus"
)

// GojaJSVM is a goja-based JavaScript VM that uses a fresh runtime per
// execution for full concurrency safety. Pre-compiled programs are replayed
// onto each new runtime to amortise parse cost.
type GojaJSVM struct {
	Spec    *APISpec
	Timeout time.Duration
	Log     *logrus.Entry  `json:"-"`
	RawLog  *logrus.Logger `json:"-"`
	Gw      *Gateway       `json:"-"`

	programs    []*goja.Program // compiled JS programs replayed on each new runtime
	initialized bool
}

// Initialized reports whether the GojaJSVM has been set up.
func (j *GojaJSVM) Initialized() bool {
	return j.initialized
}

// VM returns nil — goja does not have a persistent VM; a fresh runtime is
// created per Run() call.  This satisfies call-sites that guard on VM != nil.
func (j *GojaJSVM) VM() interface{} {
	if !j.initialized {
		return nil
	}
	// Return a non-nil sentinel so callers that check VM() != nil pass.
	return j
}

// newRuntime creates a fresh goja runtime with all loaded programs and Go API functions.
func (j *GojaJSVM) newRuntime() *goja.Runtime {
	vm := goja.New()

	// Suppress top-level log() calls during program replay.
	nop := func(call goja.FunctionCall) goja.Value { return goja.Undefined() }
	vm.Set("log", nop)
	vm.Set("rawlog", nop)

	// Replay compiled programs (middleware definitions, coreJS, etc.)
	// Programs only define functions/prototypes — no API calls at top level.
	for _, p := range j.programs {
		if _, err := vm.RunProgram(p); err != nil {
			if j.Log != nil {
				j.Log.WithError(err).Error("Failed to replay JS program")
			}
		}
	}

	// Register Go API functions (b64, HTTP, key CRUD, log, rawlog).
	// This overwrites the nop log/rawlog with real ones for request execution.
	j.registerAPI(vm)

	return vm
}

// Run executes a JS expression on a fresh runtime with timeout handling.
// Each call gets an isolated runtime so concurrent requests don't interfere.
func (j *GojaJSVM) Run(expr string) (string, error) {
	if !j.initialized {
		return "", errors.New("JSVM isn't enabled, check your gateway settings")
	}

	vm := j.newRuntime()

	timer := time.AfterFunc(j.Timeout, func() {
		vm.Interrupt("timeout")
	})
	defer timer.Stop()

	returnRaw, err := vm.RunString(expr)
	if err != nil {
		if _, ok := err.(*goja.InterruptedError); ok {
			return "", fmt.Errorf("JS middleware timed out after %v", j.Timeout)
		}
		return "", err
	}

	return returnRaw.String(), nil
}

// LoadScript compiles a JS source string and adds it to the programs list.
func (j *GojaJSVM) LoadScript(src string) error {
	p, err := goja.Compile("", src, false)
	if err != nil {
		return err
	}
	j.programs = append(j.programs, p)
	return nil
}

const defaultGojaJSVMTimeout = 5

// Init creates the GojaJSVM with the core library and sets up a default timeout.
func (j *GojaJSVM) Init(spec *APISpec, logger *logrus.Entry, gw *Gateway) {
	j.Gw = gw
	j.programs = nil
	logger = logger.WithField("prefix", "jsvm-goja")

	// Compile and store coreJS
	p, err := goja.Compile("coreJS", coreJS, false)
	if err != nil {
		logger.WithError(err).Error("Could not compile TykJS")
		return
	}
	j.programs = append(j.programs, p)

	// Load user's TykJS on top, if any
	if path := gw.GetConfig().TykJSPath; path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			p, err := goja.Compile(path, string(data), false)
			if err != nil {
				logger.WithError(err).Error("Could not compile user's TykJS")
			} else {
				j.programs = append(j.programs, p)
			}
		}
	}

	// Compile the TykJsResponse helper
	tykJsResp, err := goja.Compile("TykJsResponse", `function TykJsResponse(response, session_meta) {
		return JSON.stringify({Response: response, SessionMeta: session_meta})
	}`, false)
	if err != nil {
		logger.WithError(err).Error("Could not compile TykJsResponse")
	} else {
		j.programs = append(j.programs, tykJsResp)
	}

	j.Spec = spec
	j.initialized = true

	if jsvmTimeout := gw.GetConfig().JSVMTimeout; jsvmTimeout <= 0 {
		j.Timeout = time.Duration(defaultGojaJSVMTimeout) * time.Second
		logger.Debugf("Default JSVM timeout used: %v", j.Timeout)
	} else {
		j.Timeout = time.Duration(jsvmTimeout) * time.Second
		logger.Debugf("Custom JSVM timeout: %v", j.Timeout)
	}

	j.Log = logger
	j.RawLog = rawLog
}

func (j *GojaJSVM) DeInit() {
	j.Spec = nil
	j.Log = nil
	j.RawLog = nil
	j.Gw = nil
	j.initialized = false
}

// LoadJSPaths will load JS classes and functionality in to the VM by file
func (j *GojaJSVM) LoadJSPaths(paths []string, prefix string) {
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
		p, err := goja.Compile(mwPath, string(data), false)
		if err != nil {
			j.Log.WithError(err).Error("Failed to compile JS middleware")
			continue
		}
		j.programs = append(j.programs, p)
	}
}

func (j *GojaJSVM) registerAPI(vm *goja.Runtime) {
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
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
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
