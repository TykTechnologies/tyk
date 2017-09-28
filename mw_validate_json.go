package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/xeipuuv/gojsonschema"

	"github.com/TykTechnologies/tyk/apidef"
)

type ValidateJSON struct {
	BaseMiddleware
	schemaLoader gojsonschema.JSONLoader
}

func (k *ValidateJSON) Name() string {
	return "ValidateJSON"
}

func (k *ValidateJSON) EnabledForSpec() bool {
	for _, v := range k.Spec.VersionData.Versions {
		if len(v.ExtendedPaths.ValidateJSON) > 0 {
			return true
		}
	}

	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *ValidateJSON) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	_, versionPaths, _, _ := k.Spec.Version(r)
	found, meta := k.Spec.CheckSpecMatchesStatus(r, versionPaths, ValidateJSONRequest)
	if !found {
		return nil, http.StatusOK
	}

	vPathMeta := meta.(*apidef.ValidatePathMeta)
	if vPathMeta.ValidateWith == nil {
		return errors.New("no schemas to validate against"), http.StatusInternalServerError
	}

	rCopy := copyRequest(r)
	bodyBytes, err := ioutil.ReadAll(rCopy.Body)
	if err != nil {
		return err, http.StatusInternalServerError
	}
	defer rCopy.Body.Close()

	schema := vPathMeta.ValidateWith

	result, err := k.validate(bodyBytes, schema)
	if err != nil {
		return err, http.StatusInternalServerError
	}

	if !result.Valid() {
		errStr := "payload validation failed"
		for _, desc := range result.Errors() {
			errStr = fmt.Sprintf("%s, %s", errStr, desc)
		}

		if vPathMeta.ValidationErrorResponseCode == 0 {
			vPathMeta.ValidationErrorResponseCode = http.StatusUnprocessableEntity
		}

		return errors.New(errStr), vPathMeta.ValidationErrorResponseCode
	}

	return nil, http.StatusOK
}

func (k *ValidateJSON) validate(input []byte, schema map[string]interface{}) (*gojsonschema.Result, error) {
	inputLoader := gojsonschema.NewBytesLoader(input)

	if k.schemaLoader == nil {
		k.schemaLoader = gojsonschema.NewGoLoader(schema)
	}

	return gojsonschema.Validate(k.schemaLoader, inputLoader)
}
