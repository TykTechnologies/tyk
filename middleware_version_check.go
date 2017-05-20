package main

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
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

func (v *VersionCheck) GetName() string {
	return "VersionCheck"
}

// GetConfig retrieves the configuration from the API config
func (v *VersionCheck) GetConfig() (interface{}, error) {
	return nil, nil
}

func (v *VersionCheck) IsEnabledForSpec() bool { return true }

func (v *VersionCheck) DoMockReply(w http.ResponseWriter, meta interface{}) {
	// Reply with some alternate data
	emeta := meta.(*apidef.EndpointMethodMeta)
	responseMessage := []byte(emeta.Data)
	for header, value := range emeta.Headers {
		w.Header().Add(header, value)
	}

	w.WriteHeader(emeta.Code)
	w.Write(responseMessage)
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (v *VersionCheck) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	// Check versioning, blacklist, whitelist and ignored status
	requestValid, stat, meta := v.Spec.IsRequestValid(r)
	if !requestValid {
		// Fire a versioning failure event
		v.FireEvent(EventVersionFailure, EventVersionFailureMeta{
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
