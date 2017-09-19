package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

// RequestObject is marshalled to JSON string and passed into JSON middleware
type RequestObject struct {
	Headers map[string][]string
	Body    string
	URL     string
	Params  map[string][]string
}

type ResponseObject struct {
	Body    string
	Headers map[string]string
	Code    int
}

type VMResponseObject struct {
	Response    ResponseObject
	SessionMeta map[string]string
}

// DynamicMiddleware is a generic middleware that will execute JS code before continuing
type VirtualEndpoint struct {
	BaseMiddleware
	sh SuccessHandler
}

func (d *VirtualEndpoint) Name() string {
	return "VirtualEndpoint"
}

func preLoadVirtualMetaCode(meta *apidef.VirtualMeta, j *JSVM) {
	// the only call site uses (&foo, &bar) so meta and j won't be
	// nil.
	var src interface{}
	switch meta.FunctionSourceType {
	case "file":
		log.Debug("Loading JS Endpoint File: ", meta.FunctionSourceURI)
		f, err := os.Open(meta.FunctionSourceURI)
		if err != nil {
			log.Error("Failed to open Endpoint JS: ", err)
			return
		}
		src = f
	case "blob":
		if config.Global.DisableVirtualPathBlobs {
			log.Error("[JSVM] Blobs not allowed on this node")
			return
		}
		log.Debug("Loading JS blob")
		js, err := base64.StdEncoding.DecodeString(meta.FunctionSourceURI)
		if err != nil {
			log.Error("Failed to load blob JS: ", err)
			return
		}
		src = js
	default:
		log.Error("Type must be either file or blob (base64)!")
		return
	}
	if _, err := j.VM.Run(src); err != nil {
		log.Error("Could not load virtual endpoint JS: ", err)
	}
}

func (d *VirtualEndpoint) Init() {
	d.sh = SuccessHandler{d.BaseMiddleware}
}

func (d *VirtualEndpoint) EnabledForSpec() bool {
	if !config.Global.EnableJSVM {
		return false
	}
	for _, version := range d.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.Virtual) > 0 {
			return true
		}
	}
	return false
}

func (d *VirtualEndpoint) ServeHTTPForCache(w http.ResponseWriter, r *http.Request) *http.Response {
	_, versionPaths, _, _ := d.Spec.Version(r)
	found, meta := d.Spec.CheckSpecMatchesStatus(r, versionPaths, VirtualPath)

	if !found {
		return nil
	}

	var copiedRequest *http.Request
	if recordDetail(r) {
		copiedRequest = copyRequest(r)
	}

	t1 := time.Now().UnixNano()
	vmeta := meta.(*apidef.VirtualMeta)

	// Create the proxy object
	defer r.Body.Close()
	originalBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Error("Failed to read request body! ", err)
		return nil
	}

	requestData := RequestObject{
		Headers: r.Header,
		Body:    string(originalBody),
		URL:     r.URL.Path,
	}

	// We need to copy the body _back_ for the decode
	r.Body = ioutil.NopCloser(bytes.NewReader(originalBody))
	r.ParseForm()
	requestData.Params = r.Form

	asJsonRequestObj, err := json.Marshal(requestData)
	if err != nil {
		log.Error("Failed to encode request object for virtual endpoint: ", err)
		return nil
	}

	// Encode the configuration data too
	confData := jsonConfigData(d.Spec)

	session := new(SessionState)
	token := ctxGetAuthToken(r)

	// Encode the session object (if not a pre-process)
	if vmeta.UseSession {
		session = ctxGetSession(r)
	}

	sessionAsJsonObj, err := json.Marshal(session)
	if err != nil {
		log.Error("Failed to encode session for VM: ", err)
		return nil
	}

	// Run the middleware
	vm := d.Spec.JSVM.VM.Copy()
	returnRaw, err := vm.Run(vmeta.ResponseFunctionName + `(` + string(asJsonRequestObj) + `, ` + string(sessionAsJsonObj) + `, ` + confData + `);`)
	if err != nil {
		log.Error("Failed to run virtual endpoint JS code:", err)
		return nil
	}
	returnDataStr, _ := returnRaw.ToString()

	// Decode the return object
	newResponseData := VMResponseObject{}
	if err := json.Unmarshal([]byte(returnDataStr), &newResponseData); err != nil {
		log.Error("Failed to decode virtual endpoint response data on return from VM: ", err,
			"; Returned: ", returnDataStr)
		return nil
	}

	// Save the sesison data (if modified)
	if vmeta.UseSession {
		session.MetaData = mapStrsToIfaces(newResponseData.SessionMeta)
		d.Spec.SessionManager.UpdateSession(token, session, getLifetime(d.Spec, session))
	}

	log.Debug("JSVM Virtual Endpoint execution took: (ns) ", time.Now().UnixNano()-t1)

	copiedResponse := forceResponse(w, r, &newResponseData, d.Spec, session, false)

	go d.sh.RecordHit(r, 0, copiedResponse.StatusCode, copiedRequest, copiedResponse)

	return copiedResponse

}

func forceResponse(w http.ResponseWriter,
	r *http.Request,
	newResponseData *VMResponseObject,
	spec *APISpec,
	session *SessionState, isPre bool) *http.Response {
	responseMessage := []byte(newResponseData.Response.Body)

	// Create an http.Response object so we can send it tot he cache middleware
	newResponse := new(http.Response)
	newResponse.Header = make(map[string][]string)

	requestTime := time.Now().UTC().Format(http.TimeFormat)

	for header, value := range newResponseData.Response.Headers {
		newResponse.Header.Set(header, value)
	}

	newResponse.ContentLength = int64(len(responseMessage))
	newResponse.Body = ioutil.NopCloser(bytes.NewReader(responseMessage))
	newResponse.StatusCode = newResponseData.Response.Code
	newResponse.Proto = "HTTP/1.0"
	newResponse.ProtoMajor = 1
	newResponse.ProtoMinor = 0
	newResponse.Header.Set("Server", "tyk")
	newResponse.Header.Set("Date", requestTime)

	if !isPre {
		// Handle response middleware
		if err := handleResponseChain(spec.ResponseChain, w, newResponse, r, session); err != nil {
			log.Error("Response chain failed! ", err)
		}
	}

	// Clone the response so we can save it
	copiedRes := copyResponse(newResponse)

	handleForcedResponse(w, newResponse, session)

	// Record analytics
	return copiedRes
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (d *VirtualEndpoint) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	res := d.ServeHTTPForCache(w, r)

	if res == nil {
		return nil, 200
	}

	return nil, mwStatusRespond
}

func (d *VirtualEndpoint) HandleResponse(rw http.ResponseWriter, res *http.Response, ses *SessionState) {
	// Externalising this from the MW so we can re-use it elsewhere
	handleForcedResponse(rw, res, ses)
}

func handleForcedResponse(rw http.ResponseWriter, res *http.Response, ses *SessionState) {
	defer res.Body.Close()

	// Close connections
	if config.Global.CloseConnections {
		res.Header.Set("Connection", "close")
	}

	// Add resource headers
	if ses != nil {
		// We have found a session, lets report back
		res.Header.Set("X-RateLimit-Limit", strconv.Itoa(int(ses.QuotaMax)))
		res.Header.Set("X-RateLimit-Remaining", strconv.Itoa(int(ses.QuotaRemaining)))
		res.Header.Set("X-RateLimit-Reset", strconv.Itoa(int(ses.QuotaRenews)))
	}

	copyHeader(rw.Header(), res.Header)

	rw.WriteHeader(res.StatusCode)
	io.Copy(rw, res.Body)
}
