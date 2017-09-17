package jsvm

import (
	"github.com/robertkrimen/otto"
	"time"
	"os"
	"path/filepath"
	"net/url"
	"strings"
	"github.com/Sirupsen/logrus"
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/config"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"io/ioutil"
	"github.com/TykTechnologies/tyk/batch_req"
	"github.com/TykTechnologies/tyk/session"
)

type APIFuncs struct {
	AddOrUpdateKey func (keyName string, newSession *session.SessionState, dontReset bool) error
	GetSession func(key, apiID string) (session.SessionState, bool)
}

type JSVM struct {
	VM        *otto.Otto
	Timeout   time.Duration
	Log       *logrus.Logger // logger used by the JS code
	RawLog    *logrus.Logger // logger used by `rawlog` func to avoid formatting
	conf      *config.Config
	apiHandle *APIFuncs
}

var log = logger.Get()
var rawLog = logger.GetRaw()

// Init creates the JSVM with the core library (tyk.js) and sets up a
// default timeout.
func (j *JSVM) Init(conf *config.Config, APIHandle *APIFuncs) {
	j.conf = conf
	j.apiHandle = APIHandle

	vm := otto.New()

	// Init TykJS namespace, constructors etc.
	f, err := os.Open(conf.TykJSPath)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error("Could not open TykJS: ", err)
		return
	}
	if _, err := vm.Run(f); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error("Could not load TykJS: ", err)
		return
	}
	f.Close()

	j.VM = vm

	// Add environment API
	j.LoadTykJSApi()

	j.Timeout = 5 * time.Second
	j.Log = log // use the global logger by default
	j.RawLog = rawLog
}

// LoadJSPaths will load JS classes and functionality in to the VM by file
func (j *JSVM) LoadJSPaths(paths []string, pathPrefix string) {
	for _, mwPath := range paths {
		if pathPrefix != "" {
			mwPath = filepath.Join(j.getBundlePath(), pathPrefix, mwPath)
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
			}).Error("[JSVM]: Failed to base64 decode: ", err)
			return otto.Value{}
		}
		returnVal, err := j.VM.ToValue(string(out))
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("[JSVM]: Failed to base64 decode: ", err)
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
			}).Error("[JSVM]: Failed to base64 encode: ", err)
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
		resp, err := http.DefaultClient.Do(r)
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

		obj, _ := j.apiHandle.GetSession(apiKey, apiId)
		bs, _ := json.Marshal(obj)

		returnVal, err := j.VM.ToValue(string(bs))
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

		newSession := session.SessionState{}
		err := json.Unmarshal([]byte(encoddedSession), &newSession)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "jsvm",
			}).Error("[JSVM]: Failed to decode the sesison data")
			return otto.Value{}
		}

		j.apiHandle.AddOrUpdateKey(apiKey, &newSession, suppressReset == "1")

		return otto.Value{}
	})

	// Batch request method
	unsafeBatchHandler := batch_req.BatchRequestHandler{Conf: j.conf}
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

	j.VM.Run(`function TykJsResponse(response, session_meta) {
		return JSON.stringify({Response: response, SessionMeta: session_meta})
	}`)
}

func (j *JSVM) getBundlePath() string {
	return filepath.Join(j.conf.MiddlewarePath, "middleware", "bundles")
}
