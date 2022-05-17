package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/spf13/afero"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
)

func (gw *Gateway) apiOASPatchHandler(w http.ResponseWriter, r *http.Request) {
	// validate config settings
	if gw.GetConfig().UseDBAppConfigs {
		gw.respondWithServerError(w, r, errOASUseDBAppsConfig)
		return
	}

	// validate api id
	apiID, err := getApiID(r)
	if err != nil {
		gw.respondWithError(w, r, http.StatusBadRequest, err)
		return
	}

	var (
		newDef apidef.APIDefinition
		oas    oas.OAS
	)

	// decode OAS from request body
	if err := json.NewDecoder(r.Body).Decode(&oas); err != nil {
		gw.respondWithError(w, r, http.StatusBadRequest, errOASRequestMalformed)
		return
	}
	oas.ExtractTo(&newDef)

	// verify APIID matches
	if newDef.APIID != apiID {
		gw.respondWithError(w, r, http.StatusBadRequest, errOASIDDoesNotMatch)
		return
	}

	// validate OAS
	validationResult := apidef.Validate(&newDef, apidef.DefaultValidationRuleSet)
	if !validationResult.IsValid {
		err = errOASUnknown
		if validationResult.ErrorCount() > 0 {
			err = errors.New(validationResult.FirstError().Error())
		}

		gw.respondWithError(w, r, http.StatusBadRequest, fmt.Errorf(msgErrOASValidationFailed, err))
		return
	}

	// get existing API spec by ID
	current := gw.getApiSpec(newDef.APIID)
	if current == nil {
		gw.respondWithError(w, r, http.StatusBadRequest, errOASNoSuchAPI)
		return
	}

	// replace current OAS with provided OAS
	// this is probably ok for 4.0, but not for
	// 4.1-4.3 (x-tyk-api-gateway, query params)
	current.OAS = oas

	fs := afero.NewOsFs()

	// api
	err, errCode := gw.writeToFile(fs, newDef, newDef.APIID)
	if err != nil {
		gw.respondWithError(w, r, errCode, err)
		return
	}

	// oas
	err, errCode = gw.writeToFile(fs, &oas, newDef.APIID+"-oas")
	if err != nil {
		gw.respondWithError(w, r, errCode, err)
		return
	}

	gw.respond(w, &apiModifyKeySuccess{
		Key:    newDef.APIID,
		Status: "ok",
		Action: "modified",
	})
}
