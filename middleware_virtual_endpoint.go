package main

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/TykTechnologies/tykcommon"
	"github.com/gorilla/context"
	"github.com/mitchellh/mapstructure"
)

// RequestObject is marshalled to JSON string and pased into JSON middleware
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
	*TykMiddleware
	sh SuccessHandler
}

func PreLoadVirtualMetaCode(meta *tykcommon.VirtualMeta, j *JSVM) {
	if j == nil {
		log.Error("No JSVM loaded, cannot init methods")
		return
	}
	if meta != nil {
		if meta.FunctionSourceType == "file" {
			js, loadErr := ioutil.ReadFile(meta.FunctionSourceURI)
			if loadErr != nil {
				log.Error("Failed to load Endpoint JS: ", loadErr)
			} else {
				// No error, load the JS into the VM
				log.Debug("Loading JS Endpoint File: ", meta.FunctionSourceURI)
				j.VM.Run(js)
			}
		} else if meta.FunctionSourceType == "blob" {
			if config.DisableVirtualPathBlobs {
				log.Error("[JSVM] Blobs not allowerd on this node")
				return
			}

			js, loadErr := b64.StdEncoding.DecodeString(meta.FunctionSourceURI)
			if loadErr != nil {
				log.Error("Failed to load blob JS: ", loadErr)
			} else {
				// No error, load the JS into the VM
				log.Debug("Loading JS blob")
				j.VM.Run(js)
			}
		} else {
			log.Error("Type must be either file or blob (b64)!")
		}
	}
}

type VirtualEndpointConfig struct {
	ConfigData map[string]string `mapstructure:"config_data" bson:"config_data" json:"config_data"`
}

// New lets you do any initialisations for the object can be done here
func (d *VirtualEndpoint) New() {
	d.sh = SuccessHandler{d.TykMiddleware}
}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (d *VirtualEndpoint) GetConfig() (interface{}, error) {
	var thisModuleConfig VirtualEndpointConfig

	err := mapstructure.Decode(d.TykMiddleware.Spec.APIDefinition.RawData, &thisModuleConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return thisModuleConfig, nil
}

func (d *VirtualEndpoint) IsEnabledForSpec() bool {
	var used bool

	if config.EnableJSVM == false {
		return false
	}

	for _, thisVersion := range d.TykMiddleware.Spec.VersionData.Versions {
		if len(thisVersion.ExtendedPaths.Virtual) > 0 {
			used = true
			break
		}
	}

	return used
}

func (d *VirtualEndpoint) ServeHTTPForCache(w http.ResponseWriter, r *http.Request) *http.Response {

	// Check if we are even using this MW
	var stat RequestStatus
	var meta interface{}
	var found bool

	_, versionPaths, _, _ := d.TykMiddleware.Spec.GetVersionData(r)
	found, meta = d.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, VirtualPath)

	if found {
		stat = StatusVirtualPath
	} else {
		return nil
	}

	if stat != StatusVirtualPath {
		return nil
	}

	var copiedRequest *http.Request
	if RecordDetail(r) {
		copiedRequest = CopyHttpRequest(r)
	}

	t1 := time.Now().UnixNano()
	thisMeta := meta.(*tykcommon.VirtualMeta)

	// Create the proxy object
	defer r.Body.Close()
	originalBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Error("Failed to read request body! ", err)
		return nil
	}

	thisRequestData := RequestObject{
		Headers: r.Header,
		Body:    string(originalBody),
		URL:     r.URL.Path,
	}

	// We need to copy the body _back_ for the decode
	r.Body = nopCloser{bytes.NewBuffer(originalBody)}
	r.ParseForm()
	thisRequestData.Params = r.Form

	asJsonRequestObj, encErr := json.Marshal(thisRequestData)
	if encErr != nil {
		log.Error("Failed to encode request object for virtual endpoint: ", encErr)
		return nil
	}

	// Encode the configuration data too
	configData, cErr := d.GetConfig()
	if cErr != nil {
		log.Error("Failed to parse configuration data: ", cErr)
		configData = make(map[string]string)
	}

	asJsonConfigData, encErr := json.Marshal(configData)
	if encErr != nil {
		log.Error("Failed to encode request object for virtual endpoint: ", encErr)
		return nil
	}

	var thisSessionState = SessionState{}
	var authHeaderValue = ""

	// Encode the session object (if not a pre-process)
	if thisMeta.UseSession {
		thisSessionState = context.Get(r, SessionData).(SessionState)
		authHeaderValue = context.Get(r, AuthHeaderValue).(string)
	}

	sessionAsJsonObj, sessEncErr := json.Marshal(thisSessionState)

	if sessEncErr != nil {
		log.Error("Failed to encode session for VM: ", sessEncErr)
		return nil
	}

	// Run the middleware
	thisVM := d.Spec.JSVM.VM.Copy()
	returnRaw, _ := thisVM.Run(thisMeta.ResponseFunctionName + `(` + string(asJsonRequestObj) + `, ` + string(sessionAsJsonObj) + `, ` + string(asJsonConfigData) + `);`)
	returnDataStr, _ := returnRaw.ToString()

	// Decode the return object
	newResponseData := VMResponseObject{}
	decErr := json.Unmarshal([]byte(returnDataStr), &newResponseData)

	if decErr != nil {
		log.Error("Failed to decode virtual endpoint response data on return from VM: ", decErr)
		log.Error("--> Returned: ", returnDataStr)
		return nil
	}

	// Save the sesison data (if modified)
	if thisMeta.UseSession {
		thisSessionState.MetaData = newResponseData.SessionMeta
		d.Spec.SessionManager.UpdateSession(authHeaderValue, thisSessionState, GetLifetime(d.Spec, &thisSessionState))
	}

	log.Debug("JSVM Virtual Endpoint execution took: (ns) ", time.Now().UnixNano()-t1)

	responseMessage := []byte(newResponseData.Response.Body)

	// Create an http.Response object so we can send it tot he cache middleware
	newResponse := new(http.Response)
	newResponse.Header = make(map[string][]string)

	requestTime := time.Now().UTC().Format(http.TimeFormat)

	for header, value := range newResponseData.Response.Headers {
		newResponse.Header.Add(header, value)
	}

	newResponse.ContentLength = int64(len(responseMessage))
	newResponse.Body = ioutil.NopCloser(bytes.NewReader(responseMessage))
	newResponse.StatusCode = newResponseData.Response.Code
	newResponse.Proto = "HTTP/1.0"
	newResponse.ProtoMajor = 1
	newResponse.ProtoMinor = 0
	newResponse.Header.Add("Server", "tyk")
	newResponse.Header.Add("Date", requestTime)

	// Handle response middleware
	ResponseHandler := ResponseChain{}

	chainErr := ResponseHandler.Go(d.TykMiddleware.Spec.ResponseChain, w, newResponse, r, &thisSessionState)
	if chainErr != nil {
		log.Error("Response chain failed! ", chainErr)
	}

	// deep logging
	var copiedResponse *http.Response
	if RecordDetail(r) {
		copiedResponse = CopyHttpResponse(newResponse)
	}

	// Clone the response so we can save it
	copiedRes := new(http.Response)
	*copiedRes = *newResponse // includes shallow copies of maps, but okay

	defer newResponse.Body.Close()

	// Buffer body data
	var bodyBuffer bytes.Buffer
	bodyBuffer2 := new(bytes.Buffer)

	io.Copy(&bodyBuffer, newResponse.Body)
	*bodyBuffer2 = bodyBuffer

	// Create new ReadClosers so we can split output
	newResponse.Body = ioutil.NopCloser(&bodyBuffer)
	copiedRes.Body = ioutil.NopCloser(bodyBuffer2)

	d.HandleResponse(w, newResponse, &thisSessionState)

	// Record analytics
	go d.sh.RecordHit(w, r, 0, newResponse.StatusCode, copiedRequest, copiedResponse)

	return copiedRes

}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (d *VirtualEndpoint) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

	res := d.ServeHTTPForCache(w, r)

	if res == nil {
		return nil, 200
	}

	return nil, 666
}

func (d *VirtualEndpoint) HandleResponse(rw http.ResponseWriter, res *http.Response, ses *SessionState) error {

	defer res.Body.Close()

	// Close connections
	if config.CloseConnections {
		res.Header.Set("Connection", "close")
	}

	// Add resource headers
	if ses != nil {
		// We have found a session, lets report back
		res.Header.Add("X-RateLimit-Limit", strconv.Itoa(int(ses.QuotaMax)))
		res.Header.Add("X-RateLimit-Remaining", strconv.Itoa(int(ses.QuotaRemaining)))
		res.Header.Add("X-RateLimit-Reset", strconv.Itoa(int(ses.QuotaRenews)))
	}

	copyHeader(rw.Header(), res.Header)

	rw.WriteHeader(res.StatusCode)
	io.Copy(rw, res.Body)
	return nil
}
