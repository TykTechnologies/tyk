package main

import (
	"github.com/gorilla/context"
	"github.com/lonelycode/tykcommon"
	"net/http"
	"strings"
)

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type TransformHeaders struct {
	*TykMiddleware
}

const TYK_META_LABEL string = "$tyk_meta."

type TransformHeadersConfig struct{}

// New lets you do any initialisations for the object can be done here
func (t *TransformHeaders) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (t *TransformHeaders) GetConfig() (interface{}, error) {
	return nil, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformHeaders) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

	// Uee the request status validator to see if it's in our cache list
	var stat RequestStatus
	var meta interface{}
	var found bool

	_, versionPaths, _, _ := t.TykMiddleware.Spec.GetVersionData(r)
	found, meta = t.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, HeaderInjected)
	if found {
		stat = StatusHeaderInjected
	}

	if stat == StatusHeaderInjected {
		thisMeta := meta.(*tykcommon.HeaderInjectionMeta)

		for _, dKey := range thisMeta.DeleteHeaders {
			r.Header.Del(dKey)
		}

		ses, found := context.GetOk(r, SessionData)
		var thisSessionState SessionState
		if found {
			thisSessionState = ses.(SessionState)
		}

		for nKey, nVal := range thisMeta.AddHeaders {
			if strings.Contains(nVal, TYK_META_LABEL) {
				// Using meta_data key
				log.Debug("Meta data key in use")
				if found {
					metaKey := strings.Replace(nVal, TYK_META_LABEL, "", 1)
					if thisSessionState.MetaData != nil {
						tempVal, ok := thisSessionState.MetaData.(map[string]interface{})[metaKey]
						if ok {
							nVal = tempVal.(string)
							r.Header.Add(nKey, nVal)
						} else {
							log.Warning("Session Meta Data not found for key in map: ", metaKey)
						}

					} else {
						log.Debug("Meta data object is nil! Skipping.")
					}
				}

			} else {
				r.Header.Add(nKey, nVal)
			}

		}

	}

	return nil, 200
}
