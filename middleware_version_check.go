package main
import (
	"github.com/lonelycode/tykcommon"
	"errors"
	"net/http"
)

// VersionCheck will check whether the version of the requested API the request is accessing has any restrictions on URL endpoints
type VersionCheck struct {
	TykMiddleware
}

// New lets you do any initialisations for the object can be done here
func (v *VersionCheck) New() {}

// GetConfig retrieves the configuration from the API config
func (v *VersionCheck) GetConfig() (interface{}, error) {
	return nil, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (v *VersionCheck) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	// Check versioning, blacklist, whitelist and ignored status
	requestValid, stat, meta := v.TykMiddleware.Spec.IsRequestValid(r)
	if requestValid == false {
		// Fire a versioning failure event
		go v.TykMiddleware.FireEvent(EVENT_VersionFailure,
			EVENT_VersionFailureMeta{
				EventMetaDefault: EventMetaDefault{Message: "Attempted access to disallowed version / path."},
				Path:             r.URL.Path,
				Origin:           r.RemoteAddr,
				Key:              "",
				Reason:           string(stat),
			})
		return errors.New(string(stat)), 409
	}

	if stat == StatusOkAndIgnore {
		handler := SuccessHandler{v.TykMiddleware}
		// Skip all other execution
		handler.ServeHTTP(w, r)
		return nil, 666
	}

	if stat == StatusRedirectFlowByReply {
		// Reply with some alternate data
		thisMeta := meta.(tykcommon.EndpointMethodMeta)
		responseMessage := []byte(thisMeta.Data)
		for header, value := range(thisMeta.Headers) {
			w.Header().Add(header, value)
		}
		DoJSONWrite(w, thisMeta.Code, responseMessage)
		return nil, 666
	}

	return nil, 200
}
