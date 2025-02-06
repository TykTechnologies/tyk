package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/service/gojsonschema"
)

type ValidateJSON struct {
	*BaseMiddleware
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
	versionInfo, _ := k.Spec.Version(r)
	versionPaths := k.Spec.RxPaths[versionInfo.Name]
	found, meta := k.Spec.CheckSpecMatchesStatus(r, versionPaths, ValidateJSONRequest)
	if !found {
		return nil, http.StatusOK
	}

	vPathMeta := meta.(*apidef.ValidatePathMeta)
	if vPathMeta.Schema == nil {
		return errors.New("no schemas to validate against"), http.StatusInternalServerError
	}

	nopCloseRequestBody(r)
	// Load input body into gojsonschema
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return err, http.StatusBadRequest
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	defer r.Body.Close()
	inputLoader := gojsonschema.NewBytesLoader(bodyBytes)

	// Perform validation
	result, err := gojsonschema.Validate(vPathMeta.SchemaCache, inputLoader)
	if err != nil {
		return fmt.Errorf("JSON parsing error: %w", err), http.StatusBadRequest
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
