//go:build jq
// +build jq

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

type TransformJQMiddleware struct {
	BaseMiddleware
}

// JQResult structure stores the result of Tyk-JQ filter.
// It means that the result of the filter must contains the following fields
type JQResult struct {
	Body           interface{}            `mapstructure:"body"`
	RewriteHeaders map[string]string      `mapstructure:"rewrite_headers"`
	TykContext     map[string]interface{} `mapstructure:"tyk_context"`
}

func (t *TransformJQMiddleware) Name() string {
	return "TransformJQMiddleware"
}

func (t *TransformJQMiddleware) EnabledForSpec() bool {

	for _, version := range t.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.TransformJQ) > 0 {
			return true
		}
	}
	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformJQMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	vInfo, _ := t.Spec.Version(r)

	versionPaths, _ := a.RxPaths[vInfo.Name]

	found, meta := t.Spec.CheckSpecMatchesStatus(r, versionPaths, TransformedJQ)
	if !found {
		return nil, http.StatusOK
	}

	err := t.transformJQBody(r, meta.(*TransformJQSpec))
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "inbound-transform-jq",
			"server_name": t.Spec.Proxy.TargetURL,
			"api_id":      t.Spec.APIID,
			"path":        r.URL.Path,
		}).Error(err)
		return err, 415
	}
	return nil, http.StatusOK
}

func (t *TransformJQMiddleware) transformJQBody(r *http.Request, ts *TransformJQSpec) error {
	defer r.Body.Close()

	var bodyObj interface{}
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&bodyObj)

	// Do not fail if the body is empty
	if err != nil && err != io.EOF {
		return err
	}

	jqObj := map[string]interface{}{
		"body":         bodyObj,
		"_tyk_context": ctxGetData(r),
	}

	jqResult, err := lockedJQTransform(t.Spec, ts, jqObj)
	if err != nil {
		return err
	}

	transformed, _ := json.Marshal(jqResult.Body)
	bodyBuffer := bytes.NewBuffer(transformed)
	r.Body = ioutil.NopCloser(bodyBuffer)
	r.ContentLength = int64(bodyBuffer.Len())
	t
	// Replace header in the request
	ignoreCanonical := t.GetConfig().IgnoreCanonicalMIMEHeaderKey
	for hName, hValue := range jqResult.RewriteHeaders {
		setCustomHeader(r.Header, hName, hValue, ignoreCanonical)
	}

	if t.Spec.EnableContextVars {
		// Set variables in context vars
		contextDataObject := ctxGetData(r)
		for k, v := range jqResult.TykContext {
			contextDataObject[k] = v
		}
		ctxSetData(r, contextDataObject)
	}

	return nil
}

func lockedJQTransform(s *APISpec, t *TransformJQSpec, jqObj map[string]interface{}) (JQResult, error) {
	s.Lock()
	value, err := t.JQFilter.Handle(jqObj)
	s.Unlock()
	if err != nil {
		return JQResult{}, err
	}
	// The filter MUST return the following JSON object
	//  {
	//    "body": THE_TRANSFORMED_BODY,
	//    "rewrite_headers": {"header1_name": "header1_value", ...},
	//    "tyk_context": {"var1_name": "var1_value", ...}
	//  }

	var jqResult JQResult
	values, ok := value.(map[string]interface{})
	if !ok {
		return JQResult{}, errors.New("Invalid JSON object returned by JQ filter. Allowed field are 'body', 'rewrite_headers' and 'tyk_context'")
	}

	jqResult.Body = values["body"]

	headers, converted := values["rewrite_headers"].(map[string]interface{})
	if !converted {
		log.Error("rewrite_headers field must be a JSON object of string/string pairs")
	} else {
		jqResult.RewriteHeaders = make(map[string]string)
		for k, v := range headers {
			switch x := v.(type) {
			case string:
				jqResult.RewriteHeaders[k] = x
			default:
				log.Errorf("rewrite_header field must be a JSON object of string/string pairs (%s isn't)", k)
			}
		}
	}

	jqResult.TykContext, _ = values["tyk_context"].(map[string]interface{})

	return jqResult, nil
}

type TransformJQSpec struct {
	apidef.TransformJQMeta
	JQFilter *JQ
}

func (a *APIDefinitionLoader) compileTransformJQPathSpec(paths []apidef.TransformJQMeta, stat URLStatus, conf config.Config) []URLSpec {
	urlSpec := []URLSpec{}

	log.Debug("Checking for JQ tranform paths ...")
	for _, stringSpec := range paths {
		newSpec := URLSpec{}
		a.generateRegex(stringSpec.Path, &newSpec, stat, conf)
		newTransformSpec := TransformJQSpec{TransformJQMeta: stringSpec}

		var err error
		newTransformSpec.JQFilter, err = NewJQ(stringSpec.Filter)

		if stat == TransformedJQ {
			newSpec.TransformJQAction = newTransformSpec
		} else {
			newSpec.TransformJQResponseAction = newTransformSpec
		}

		if err == nil {
			urlSpec = append(urlSpec, newSpec)
		} else {
			log.Error("JQ Filter load failure! Skipping transformation: ", err)
		}
	}

	return urlSpec
}
