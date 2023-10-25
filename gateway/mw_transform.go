package gateway

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
	vInfo, _ := t.Spec.Version(r)
	versionPaths := t.Spec.RxPaths[vInfo.Name]
	found, meta := t.Spec.CheckSpecMatchesStatus(r, versionPaths, Transformed)
	if !found {
		return nil, http.StatusOK
	}
	err := transformBody(r, meta.(*TransformSpec), t)
	if err != nil {
		t.Logger().WithError(err).Error("Body transform failure")
	}
	return nil, http.StatusOK
}

func transformBody(r *http.Request, tmeta *TransformSpec, t *TransformMiddleware) error {
	body, _ := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	// Put into an interface:
	bodyData := make(map[string]interface{})

	switch tmeta.TemplateData.Input {
	case apidef.RequestXML:
		if len(body) == 0 {
			body = []byte("<_/>")
		}
		mxj.XmlCharsetReader = WrappedCharsetReader
		var err error
		bodyData, err = mxj.NewMapXml(body) // unmarshal
		if err != nil {
			return fmt.Errorf("error unmarshalling XML: %v", err)
		}
	case apidef.RequestJSON:
		if len(body) == 0 {
			body = []byte("{}")
		}

		var tempBody interface{}
		if err := json.Unmarshal(body, &tempBody); err != nil {
			return err
		}

		switch tempBody.(type) {
		case []interface{}:
			bodyData["array"] = tempBody
		case map[string]interface{}:
			bodyData = tempBody.(map[string]interface{})
		}
	default:
		return fmt.Errorf("unsupported request input type: %v", tmeta.TemplateData.Input)
	}

	if tmeta.TemplateData.EnableSession {
		if session := ctxGetSession(r); session != nil {
			bodyData["_tyk_meta"] = session.MetaData
		} else {
			log.Error("Session context was enabled but not found.")
		}
	}

	if t.Spec.EnableContextVars {
		bodyData["_tyk_context"] = ctxGetData(r)
	}

	// Apply to template
	var bodyBuffer bytes.Buffer
	if err := tmeta.Template.Execute(&bodyBuffer, bodyData); err != nil {
		return fmt.Errorf("failed to apply template to request: %v", err)
	}

	s := t.Gw.replaceTykVariables(r, bodyBuffer.String(), true)

	newBuf := bytes.NewBufferString(s)

	r.Body = io.NopCloser(newBuf)

	r.ContentLength = int64(newBuf.Len())
	nopCloseRequestBody(r)

	return nil
}
