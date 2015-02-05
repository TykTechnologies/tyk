package main

import (
	"net/http"
    "io/ioutil"
    "encoding/json"
    "bytes"
    "github.com/lonelycode/tykcommon"
)

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type TransformMiddleware struct {
	TykMiddleware
}

type TransformMiddlewareConfig struct {}

// New lets you do any initialisations for the object can be done here
func (m *TransformMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (t *TransformMiddleware) GetConfig() (interface{}, error) {
	return nil, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	  
    // New request checker, more targetted, less likely to fail
    var stat RequestStatus
    var meta interface{}
    var found bool
    
    _, versionPaths, _, _ := t.TykMiddleware.Spec.GetVersionData(r)
    found, meta = t.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, Transformed)
    if found {
        stat = StatusTransform
    }
    
    if stat == StatusTransform {
        thisMeta := meta.(TransformSpec)
        
        // Read the body:
        defer r.Body.Close()
        body, err := ioutil.ReadAll(r.Body)
        
        // Put into an interface:
        var bodyData interface{}
        switch thisMeta.TemplateMeta.TemplateData.Input {
        case tykcommon.RequestXML:
            log.Warning("XML Input is not supprted")                       
        case tykcommon.RequestJSON:
            json.Unmarshal(body, &bodyData)
        default:
            json.Unmarshal(body, &bodyData)
        }
        
        
        // Apply to template
        var bodyBuffer bytes.Buffer
        err = thisMeta.Template.Execute(&bodyBuffer, bodyData)
        if err != nil {
            log.Error("Failed to apply template to request: ", err)
        }
        r.Body = ioutil.NopCloser(&bodyBuffer)
        r.ContentLength = int64(bodyBuffer.Len())
    }

	return nil, 200
}
