package gateway

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/TykTechnologies/gojsonschema"
	"github.com/TykTechnologies/tyk/v3/apidef"
)

type ValidateJSON struct {
	BaseMiddleware
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

	if val, exists := vPathMeta.Schema["$schema"]; exists {
		if val != "http://json-schema.org/draft-04/schema#" {
			return errors.New("unsupported schema, unable to validate"), http.StatusInternalServerError
		}
	}

	// Load input body into gojsonschema
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err, http.StatusBadRequest
	}
	defer r.Body.Close()
	inputLoader := gojsonschema.NewBytesLoader(bodyBytes)

	// Perform validation
	result, err := gojsonschema.Validate(vPathMeta.SchemaCache, inputLoader)
	if err != nil {
		return fmt.Errorf("JSON parsing error: %v", err), http.StatusBadRequest
	}

	// Handle Failure
	if !result.Valid() {
		if vPathMeta.ErrorResponseCode == 0 {
			vPathMeta.ErrorResponseCode = http.StatusUnprocessableEntity
		}

		return k.formatError(result.Errors()), vPathMeta.ErrorResponseCode
	}

	// Handle Success
	return nil, http.StatusOK
}

func (k *ValidateJSON) formatError(schemaErrors []gojsonschema.ResultError) error {
	errStr := ""
	for i, desc := range schemaErrors {
		if i == 0 {
			errStr = desc.String()
		} else {
			errStr = errStr + "; " + desc.String()
		}
	}

	return errors.New(errStr)
}
