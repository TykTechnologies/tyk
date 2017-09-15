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
	*BaseMiddleware
}

type JQTransformOptions struct {
	OutputHeaders map[string]string `mapstructure:"output_headers"`
	OutputVars    map[string]string `mapstructure:"output_vars"`
}

func (t *TransformJQMiddleware) GetName() string {
	return "TransformJQMiddleware"
}

func (t *TransformJQMiddleware) IsEnabledForSpec() bool {
	for _, version := range t.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.TransformJQ) > 0 {
			return true
		}
	}
	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformJQMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	_, versionPaths, _, _ := t.Spec.GetVersionData(r)
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
	// Read the body:
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	var contextJson []byte
	if contextVars {
		contextJson, _ = json.Marshal(ctxGetData(r))
	} else {
		contextJson = []byte("{}")
	}

	bodyBuffer := bytes.NewBufferString("[")
	bodyBuffer.Write(contextJson)
	bodyBuffer.WriteString(",")
	bodyBuffer.Write(body)
	bodyBuffer.WriteString("]")

	err = t.JQFilter.HandleJson(bodyBuffer.String())
	if err != nil {
		return errors.New("Input is not a valid JSON")
	}

	// First element is the transformed body
	if t.JQFilter.Next() {
		transformed, _ := json.Marshal(t.JQFilter.Value())

		bodyBuffer := bytes.NewBuffer(transformed)
		r.Body = ioutil.NopCloser(bodyBuffer)
		r.ContentLength = int64(bodyBuffer.Len())
	} else {
		return errors.New("Errors while applying JQ filter to input")
	}

	// Second optional element is an object like:
	// { "output_headers": {"header_name": "header_value", ...},
	//   "outputs_vars":   {"var_name_1": "var_value_1", ...}
	//}
	if t.JQFilter.Next() {
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

		// Set variables in context vars
		contextDataObject := ctxGetData(r)
		for k, v := range opts.OutputVars {
			contextDataObject["jq_output_var_" + k] = v
		}

		ctxSetData(r, contextDataObject)
	} else {
		return errors.New("Options for jq transformation were specified, but are invalid")
	}

	return nil
}
