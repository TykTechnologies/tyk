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
	if vPathMeta.Schema == nil {
		return errors.New("no schemas to validate against"), http.StatusInternalServerError
	}

	if vPathMeta.SchemaVersion != "" && vPathMeta.SchemaVersion != "draft-v4" {
		return errors.New("unsupported schema version"), http.StatusInternalServerError
	}

	rCopy := copyRequest(r)
	bodyBytes, err := ioutil.ReadAll(rCopy.Body)
	if err != nil {
		return err, http.StatusBadRequest
	}
	defer rCopy.Body.Close()

	schema := vPathMeta.Schema

	result, err := k.validate(bodyBytes, schema)
	if err != nil {
		return fmt.Errorf("JSON parsing error: %v", err), http.StatusBadRequest
	}

	if !result.Valid() {
		errStr := ""
		for i, desc := range result.Errors() {
			if i == 0 {
				errStr = desc.String()
			} else {
				errStr = fmt.Sprintf("%s; %s", errStr, desc)
			}
		}

		if vPathMeta.ErrorResponseCode == 0 {
			vPathMeta.ErrorResponseCode = http.StatusUnprocessableEntity
		}

		return errors.New(errStr), vPathMeta.ErrorResponseCode
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
