package main

import (
	"errors"
	"fmt"
	"github.com/TykTechnologies/tykcommon"
	"net/http"
)

// VersionCheck will check whether the version of the requested API the request is accessing has any restrictions on URL endpoints
type VersionCheck struct {
	*TykMiddleware
	sh SuccessHandler
}

// New lets you do any initialisations for the object can be done here
func (v *VersionCheck) New() {
	v.sh = SuccessHandler{v.TykMiddleware}
}

// GetConfig retrieves the configuration from the API config
func (v *VersionCheck) GetConfig() (interface{}, error) {
	return nil, nil
}

func (a *VersionCheck) IsEnabledForSpec() bool {
	return true
}

func (v *VersionCheck) DoMockReply(w http.ResponseWriter, meta interface{}) {
	// Reply with some alternate data
	thisMeta := meta.(*tykcommon.EndpointMethodMeta)
	responseMessage := []byte(thisMeta.Data)
	for header, value := range thisMeta.Headers {
		w.Header().Add(header, value)
	}

	w.WriteHeader(thisMeta.Code)
	fmt.Fprintf(w, string(responseMessage))
	return
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (v *VersionCheck) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	// Check versioning, blacklist, whitelist and ignored status
	requestValid, stat, meta := v.TykMiddleware.Spec.IsRequestValid(r)
	if requestValid == false {
		// Fire a versioning failure event
		go v.TykMiddleware.FireEvent(EVENT_VersionFailure,
			EVENT_VersionFailureMeta{
				EventMetaDefault: EventMetaDefault{Message: "Attempted access to disallowed version / path.", OriginatingRequest: EncodeRequestToEvent(r)},
				Path:             r.URL.Path,
				Origin:           GetIPFromRequest(r),
				Key:              "",
				Reason:           string(stat),
			})
		return errors.New(string(stat)), 403
	}

	// We handle redirects before ignores in case we aren't using a whitelist
	if stat == StatusRedirectFlowByReply {
		v.DoMockReply(w, meta)
		return nil, 666
	}

	if stat == StatusOkAndIgnore {
		v.sh.ServeHTTP(w, r)
		return nil, 666
	}

	return nil, 200
}
