package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gorilla/context"
	"github.com/lonelycode/tykcommon"
	"github.com/mitchellh/mapstructure"
	"io/ioutil"
	"net/http"
	"time"
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
		} else {
			log.Error("Base64 Encoded functions are not supported yet!")
		}
	}
}

type VirtualEndpointConfig struct {
	ConfigData map[string]string `mapstructure:"config_data" bson:"config_data" json:"config_data"`
}

// New lets you do any initialisations for the object can be done here
func (d *VirtualEndpoint) New() {}

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
	returnRaw, _ := d.Spec.JSVM.VM.Run(thisMeta.ResponseFunctionName + `(` + string(asJsonRequestObj) + `, ` + string(sessionAsJsonObj) + `, ` + string(asJsonConfigData) + `);`)
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
		d.Spec.SessionManager.UpdateSession(authHeaderValue, thisSessionState, 0)
	}

	log.Debug("JSVM Virtual Endpoint execution took: (ns) ", time.Now().UnixNano()-t1)

	// Write to reply with some alternate data
	responseMessage := []byte(newResponseData.Response.Body)

	// Create an http.Response object so we can send it tot he cache middleware
	newResponse := new(http.Response)
	newResponse.Header = make(map[string][]string)

	requestTime := time.Now().UTC().Format(http.TimeFormat)
	w.Header().Add("Server", "tyk")
	w.Header().Add("Date", requestTime)

	for header, value := range newResponseData.Response.Headers {
		w.Header().Add(header, value)
		newResponse.Header.Add(header, value)
	}

	// Write to the client
	w.WriteHeader(newResponseData.Response.Code)
	fmt.Fprintf(w, string(responseMessage))

	newResponse.ContentLength = int64(len(responseMessage))
	newResponse.Body = ioutil.NopCloser(bytes.NewReader(responseMessage))
	newResponse.StatusCode = newResponseData.Response.Code
	newResponse.Proto = "HTTP/1.0"
	newResponse.ProtoMajor = 1
	newResponse.ProtoMinor = 0
	newResponse.Header.Add("Server", "tyk")
	newResponse.Header.Add("Date", requestTime)

	return newResponse

}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (d *VirtualEndpoint) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

	d.ServeHTTPForCache(w, r)

	return nil, 666
}
