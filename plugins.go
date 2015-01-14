package main

import (
	"github.com/mitchellh/mapstructure"
    "github.com/robertkrimen/otto"
	"net/http"
    "io"
    "io/ioutil"
    "encoding/json"
    "github.com/gorilla/context"
    "bytes"
)

const (
    TYKJS_PATH string = "js/tyk.js"
)

// MiniRequestObject is marshalled to JSON string and pased into JSON middleware
type MiniRequestObject struct {
    Headers map[string][]string
    SetHeaders map[string]string
    DeleteHeaders []string
    Body string
    URL string
    AddParams map[string]string
    DeleteParams []string
}

type VMReturnObject struct {
    Request MiniRequestObject    
    SessionMeta map[string]string
}

type nopCloser struct {
    io.Reader 
}

func (nopCloser) Close() error { 
    return nil 
}

// DynamicMiddleware is a generic middleware that will execute JS code before continuing
type DynamicMiddleware struct {
	TykMiddleware
    MiddlewareClassName string
    Pre bool
}

type DynamicMiddlewareConfig struct {
    ConfigData map[string]string `mapstructure:"config_data" bson:"config_data" json:"config_data"`
}

// New lets you do any initialisations for the object can be done here
func (d *DynamicMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (d *DynamicMiddleware) GetConfig() (interface{}, error) {
	var thisModuleConfig DynamicMiddlewareConfig

	err := mapstructure.Decode(d.TykMiddleware.Spec.APIDefinition.RawData, &thisModuleConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return thisModuleConfig, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (d *DynamicMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
    
	// Createthe proxy object
    defer r.Body.Close()
    originalBody, err := ioutil.ReadAll(r.Body)
    if err != nil {
        log.Error("Failed to read request body! ", err)
        return nil, 200
    }
    
    thisRequestData := MiniRequestObject{
        Headers: r.Header,
        SetHeaders: make(map[string]string),
        DeleteHeaders: make([]string, 0),
        Body: string(originalBody),
        URL: r.URL.Path,
        AddParams: make(map[string]string),
        DeleteParams: make([]string, 0),
    }
   
    asJsonRequestObj, encErr := json.Marshal(thisRequestData)
    if encErr != nil {
        log.Error("Failed to encode request object for dynamic middleware: ", encErr)
        return nil, 200
    }
    
    var thisSessionState = SessionState{}
    var authHeaderValue = ""
    
    // Encode the session object (if not a pre-process)
    if !d.Pre {
        thisSessionState = context.Get(r, SessionData).(SessionState)
        authHeaderValue = context.Get(r, AuthHeaderValue).(string)    
    }
    
    sessionAsJsonObj, sessEncErr := json.Marshal(thisSessionState)

    if sessEncErr != nil {
        log.Error("Failed to encode session for VM: ", sessEncErr)
        return nil, 200
    }   
    
    
    // Run the middleware
    middlewareClassname := d.MiddlewareClassName
    returnRaw, _ := d.Spec.JSVM.Run(middlewareClassname + `.DoProcessRequest(` + string(asJsonRequestObj) + `, ` + string(sessionAsJsonObj) + `);`)
	returnDataStr, _ := returnRaw.ToString()
    
    // Decode the return object
    newRequestData := VMReturnObject{}
    decErr := json.Unmarshal([]byte(returnDataStr), &newRequestData)
    
    if decErr != nil {
        log.Error("Failed to decode middleware request data on return from VM: ", decErr)
        log.Info(returnDataStr)
        return nil, 200
    }
    
    // Reconstruct the request parts
    r.ContentLength = int64(len(newRequestData.Request.Body))    
    r.Body = nopCloser{bytes.NewBufferString(newRequestData.Request.Body)} 
    r.URL.Path = newRequestData.Request.URL
    
    // Delete and set headers
    for _, dh := range(newRequestData.Request.DeleteHeaders) {
        r.Header.Del(dh)
    }
    
    for h, v := range(newRequestData.Request.SetHeaders) {
        r.Header.Set(h, v)
    }
    
    // Delete and set request parameters
    values := r.URL.Query()
    for _, k := range(newRequestData.Request.DeleteParams) {
        values.Del(k)
    }
    
    for p, v := range(newRequestData.Request.AddParams) {
        values.Set(p, v)
    }
    
    r.URL.RawQuery = values.Encode()
    
    // Save the sesison data (if modified)
    if !d.Pre {
        thisSessionState.MetaData = newRequestData.SessionMeta
        d.Spec.SessionManager.UpdateSession(authHeaderValue, thisSessionState, 0)
    }
    
	return nil, 200
}

// --- Utility functions during startup to ensure a sane VM is present for each API Def ----


// CreateJSVM Creates a new VM object for an API to load middleware into
func CreateJSVM(middlewarePaths []string) *otto.Otto {
    vm := otto.New()
    coreJs, _ := ioutil.ReadFile(TYKJS_PATH)
	// run core elements

	vm.Set("log", func(call otto.FunctionCall) otto.Value {
			log.Info("JSVM LOG: ", call.Argument(0).String())
			return otto.Value{}
	})

	vm.Run(coreJs)
    
    for _, mwPath := range(middlewarePaths) {
        js, loadErr := ioutil.ReadFile(mwPath)
        if loadErr != nil {
            log.Error("Failed to load Middleware JS: ", loadErr)
        } else {
            // No error, load the JS into the VM
            vm.Run(js)
        }
    }
    
    return vm
}