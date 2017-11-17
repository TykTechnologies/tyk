package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/clbanning/mxj"
	"golang.org/x/net/html/charset"

	"github.com/TykTechnologies/tyk/apidef"
)

func WrappedCharsetReader(s string, i io.Reader) (io.Reader, error) {
	return charset.NewReader(i, s)
}

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type TransformMiddleware struct {
	BaseMiddleware
}

func (t *TransformMiddleware) Name() string {
	return "TransformMiddleware"
}

func (t *TransformMiddleware) EnabledForSpec() bool {
	for _, version := range t.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.Transform) > 0 {
			return true
		}
	}
	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	_, versionPaths, _, _ := t.Spec.Version(r)
	found, meta := t.Spec.CheckSpecMatchesStatus(r, versionPaths, Transformed)
	if !found {
		return nil, 200
	}
	err := transformBody(r, meta.(*TransformSpec), t.Spec.EnableContextVars)
	if err != nil {
		logEntry := getLogEntryForRequest(
			r,
			"",
			map[string]interface{}{
				"prefix":      "inbound-transform",
				"server_name": t.Spec.Proxy.TargetURL,
				"api_id":      t.Spec.APIID,
			},
		)
		logEntry.Error(err)
	}
	return nil, 200
}

func transformBody(r *http.Request, tmeta *TransformSpec, contextVars bool) error {
	// Read the body:
	defer r.Body.Close()

	// Put into an interface:
	bodyData := make(map[string]interface{})
	switch tmeta.TemplateData.Input {
	case apidef.RequestXML:
		mxj.XmlCharsetReader = WrappedCharsetReader
		var err error
		bodyData, err = mxj.NewMapXmlReader(r.Body) // unmarshal
		if err != nil {
			return fmt.Errorf("error unmarshalling XML: %v", err)
		}
	case apidef.RequestJSON:
		if err := json.NewDecoder(r.Body).Decode(&bodyData); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported request input type: %v", tmeta.TemplateData.Input)
	}

	if tmeta.TemplateData.EnableSession {
		session := ctxGetSession(r)
		bodyData["_tyk_meta"] = session.MetaData
	}

	if contextVars {
		bodyData["_tyk_context"] = ctxGetData(r)
	}

	// Apply to template
	var bodyBuffer bytes.Buffer
	if err := tmeta.Template.Execute(&bodyBuffer, bodyData); err != nil {
		return fmt.Errorf("failed to apply template to request: %v", err)
	}
	r.Body = ioutil.NopCloser(&bodyBuffer)
	r.ContentLength = int64(bodyBuffer.Len())

	return nil
}
