package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/xeipuuv/gojsonschema"

	"github.com/TykTechnologies/tyk/apidef"
)

var serverError error = errors.New("validation failed, server error")

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
		return nil, 200
	}
	mmeta := meta.(*apidef.ValidatePathMeta)

	if mmeta.ValidateWith == "" {
		return serverError, 400

	}

	rCopy := copyRequest(r)
	body, err := ioutil.ReadAll(rCopy.Body)
	if err != nil {
		log.Error("")
		return serverError, 400
	}

	return validateJSONSchema(mmeta.ValidateWith, string(body))
}

func getJSONSchemaLoader(rawString string) (gojsonschema.JSONLoader, error) {
	sDec, err := base64.StdEncoding.DecodeString(rawString)
	if err != nil {
		return nil, err
	}

	ldr := gojsonschema.NewStringLoader(string(sDec))
	return ldr, nil
}

func validateJSONSchema(validateWith string, body string) (error, int) {
	sch, err := getJSONSchemaLoader(validateWith)

	if err != nil {
		log.Error("Can't continue with request validation, failed to retrieve schema: ", err)
		return serverError, 400
	}

	ldr := gojsonschema.NewStringLoader(string(body))

	result, err := gojsonschema.Validate(sch, ldr)
	if err != nil {
		log.Error("Can't continue with request validation, process failed: ", err)
		return serverError, 400
	}

	if !result.Valid() {
		errStr := "payload validation failed"
		for _, desc := range result.Errors() {
			errStr = fmt.Sprintf("%s: %s", errStr, desc)
		}
		return errors.New(errStr), 400
	}

	return nil, 200
}
