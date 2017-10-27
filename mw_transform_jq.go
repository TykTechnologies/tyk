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

type JQTransformOptions struct {
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

	if err := t.JQFilter.Handle(jqObj); err != nil {
		return err
	}

	// First element is the transformed body
	if !t.JQFilter.Next() {
		return errors.New("Errors while applying JQ filter to input")
	}

	transformed, _ := json.Marshal(t.JQFilter.Value())

	var bodyBuffer = bytes.NewBuffer(transformed)
	r.Body = ioutil.NopCloser(bodyBuffer)
	r.ContentLength = int64(bodyBuffer.Len())

	// Second optional element is an object like:
	// { "output_headers": {"header_name": "header_value", ...},
	//   "outputs_vars":   {"var_name_1": "var_value_1", ...}
	// }
	if !t.JQFilter.Next() {
		return nil
	}

	options := t.JQFilter.Value()

	var opts JQTransformOptions
	err := mapstructure.Decode(options, &opts)
	if err != nil {
		return errors.New("Errors while reading JQ filter transform options")
	}

	// Replace header in the request
	for hName, hValue := range opts.OutputHeaders {
		r.Header.Set(hName, hValue)
	}

	if contextVars {
		// Set variables in context vars
		contextDataObject := ctxGetData(r)
		for k, v := range opts.OutputVars {
			contextDataObject["jq_output_var_"+k] = v
		}
		ctxSetData(r, contextDataObject)
	} else {
		log.Warn("You specified a JQ filter returning output variables, but enable_context_vars is false")
	}

	return nil
}
