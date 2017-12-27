package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/Sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
)

type TransformJQMiddleware struct {
	BaseMiddleware
}

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
	_, versionPaths, _, _ := t.Spec.Version(r)
	found, meta := t.Spec.CheckSpecMatchesStatus(r, versionPaths, TransformedJQ)
	if !found {
		return nil, 200
	}

	err := transformJQBody(r, meta.(*TransformJQSpec), t.Spec.EnableContextVars)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "inbound-transform-jq",
			"server_name": t.Spec.Proxy.TargetURL,
			"api_id":      t.Spec.APIID,
			"path":        r.URL.Path,
		}).Error(err)
		return err, 415
	}
	return nil, 200
}

func transformJQBody(r *http.Request, t *TransformJQSpec, contextVars bool) error {
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

	jq_result, err := lockedJQTransform(t, jqObj)
	if err != nil {
		return err
	}

	transformed, _ := json.Marshal(jq_result.Body)
	bodyBuffer := bytes.NewBuffer(transformed)
	r.Body = ioutil.NopCloser(bodyBuffer)
	r.ContentLength = int64(bodyBuffer.Len())

	// Replace header in the request
	for hName, hValue := range jq_result.RewriteHeaders {
		r.Header.Set(hName, hValue)
	}

	if contextVars {
		// Set variables in context vars
		contextDataObject := ctxGetData(r)
		for k, v := range jq_result.TykContext {
			contextDataObject[k] = v
		}
		ctxSetData(r, contextDataObject)
	}

	return nil
}

func lockedJQTransform(t *TransformJQSpec, jqObj map[string]interface{}) (JQResult, error) {
	t.Lock()
	value, err := t.JQFilter.Handle(jqObj)
	t.Unlock()
	if err != nil {
		return JQResult{}, err
	}
	// The filter MUST return the following JSON object
	//  {
	//    "body": THE_TRANSFORMED_BODY,
	//    "rewrite_headers": {"header1_name": "header1_value", ...},
	//    "tyk_context": {"var1_name": "var1_value", ...}
	//  }

	var jq_result JQResult
	values, ok := value.(map[string]interface{})
	if !ok {
		return JQResult{}, errors.New("Invalid JSON object returned by JQ filter. Allowed field are 'body', 'rewrite_headers' and 'tyk_context'")
	}

	jq_result.Body = values["body"]

	headers, converted := values["rewrite_headers"].(map[string]interface{})
	if !converted {
		log.Error("rewrite_headers field must be a JSON object of string/string pairs")
	} else {
		jq_result.RewriteHeaders = make(map[string]string)
		for k, v := range headers {
			switch x := v.(type) {
			case string:
				jq_result.RewriteHeaders[k] = x
			default:
				log.Errorf("rewrite_header field must be a JSON object of string/string pairs (%s isn't)", k)
			}
		}
	}

	jq_result.TykContext, _ = values["tyk_context"].(map[string]interface{})

	return jq_result, nil
}
