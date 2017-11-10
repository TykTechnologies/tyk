package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/Sirupsen/logrus"
	"github.com/mitchellh/mapstructure"
	"io/ioutil"
	"net/http"
)

type TransformJQMiddleware struct {
	BaseMiddleware
}

type JQResult struct {
	Body          interface{}       `mapstructure:"body"`
	OutputHeaders map[string]string `mapstructure:"output_headers"`
	OutputVars    map[string]string `mapstructure:"output_vars"`
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
	if err := dec.Decode(&bodyObj); err != nil {
		return err
	}

	jqObj := map[string]interface{}{
		"body":       bodyObj,
		"reqContext": ctxGetData(r),
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
	for hName, hValue := range jq_result.OutputHeaders {
		r.Header.Set(hName, hValue)
	}

	if contextVars {
		// Set variables in context vars
		contextDataObject := ctxGetData(r)
		for k, v := range jq_result.OutputVars {
			contextDataObject["jq_output_var_"+k] = v
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
	//    "output_headers": {"header1_name": "header1_value", ...},
	//    "output_vars": {"var1_name": "var1_value", ...}
	//  }

	var jq_result JQResult
	err = mapstructure.Decode(value, &jq_result)
	if err != nil {
		return JQResult{}, errors.New("Invalid JSON object returned by JQ filter. Allowed field are 'body', 'output_vars' and 'output_headers'")
	}

	return jq_result, nil
}
