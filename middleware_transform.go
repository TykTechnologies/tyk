package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/clbanning/mxj"
	"github.com/gorilla/context"
	"golang.org/x/net/html/charset"

	"github.com/TykTechnologies/logrus"
	"github.com/TykTechnologies/tyk/apidef"
)

func WrappedCharsetReader(s string, i io.Reader) (io.Reader, error) {
	return charset.NewReader(i, s)
}

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type TransformMiddleware struct {
	*TykMiddleware
}

func (t *TransformMiddleware) GetName() string {
	return "TransformMiddleware"
}

// New lets you do any initialisations for the object can be done here
func (t *TransformMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (t *TransformMiddleware) GetConfig() (interface{}, error) {
	return nil, nil
}

func (t *TransformMiddleware) IsEnabledForSpec() bool {
	var used bool
	for _, version := range t.TykMiddleware.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.Transform) > 0 {
			used = true
			break
		}
	}

	return used
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	_, versionPaths, _, _ := t.TykMiddleware.Spec.GetVersionData(r)
	found, meta := t.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, Transformed)
	if found {
		tmeta := meta.(*TransformSpec)

		// Read the body:
		defer r.Body.Close()
		body, err := ioutil.ReadAll(r.Body)

		// Put into an interface:
		var bodyData interface{}
		switch tmeta.TemplateMeta.TemplateData.Input {
		case apidef.RequestXML:
			mxj.XmlCharsetReader = WrappedCharsetReader
			var err error
			bodyData, err = mxj.NewMapXml(body) // unmarshal
			if err != nil {
				log.WithFields(logrus.Fields{
					"prefix":      "inbound-transform",
					"server_name": t.Spec.APIDefinition.Proxy.TargetURL,
					"api_id":      t.Spec.APIDefinition.APIID,
					"path":        r.URL.Path,
				}).Error("Error unmarshalling XML: ", err)
			}
		case apidef.RequestJSON:
			json.Unmarshal(body, &bodyData)
		default:
			// unset, assume an open field
			bodyData = make(map[string]interface{})
		}

		if tmeta.TemplateMeta.TemplateData.EnableSession {
			ses := context.Get(r, SessionData).(SessionState)
			switch bodyData.(type) {
			case map[string]interface{}:
				bodyData.(map[string]interface{})["_tyk_meta"] = ses.MetaData
			}
		}

		if t.Spec.EnableContextVars {
			contextData := context.Get(r, ContextData)
			switch bodyData.(type) {
			case map[string]interface{}:
				bodyData.(map[string]interface{})["_tyk_context"] = contextData
			}
		}

		// Apply to template
		var bodyBuffer bytes.Buffer
		if err = tmeta.Template.Execute(&bodyBuffer, bodyData); err != nil {
			log.WithFields(logrus.Fields{
				"prefix":      "inbound-transform",
				"server_name": t.Spec.APIDefinition.Proxy.TargetURL,
				"api_id":      t.Spec.APIDefinition.APIID,
				"path":        r.URL.Path,
			}).Error("Failed to apply template to request: ", err)
		}
		r.Body = ioutil.NopCloser(&bodyBuffer)
		r.ContentLength = int64(bodyBuffer.Len())
	}

	return nil, 200
}
