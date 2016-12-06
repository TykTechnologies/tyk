package main

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/TykTechnologies/tykcommon"
	"github.com/gorilla/context"
)

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type TransformHeaders struct {
	*TykMiddleware
}

const TYK_META_LABEL string = "$tyk_meta."
const TYK_CONTEXT_LABEL string = "$tyk_context."

type TransformHeadersConfig struct{}

// New lets you do any initialisations for the object can be done here
func (t *TransformHeaders) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (t *TransformHeaders) GetConfig() (interface{}, error) {
	return nil, nil
}

func (t *TransformHeaders) IsEnabledForSpec() bool {
	var used bool
	for _, thisVersion := range t.TykMiddleware.Spec.VersionData.Versions {
		if len(thisVersion.ExtendedPaths.TransformHeader) > 0 {
			used = true
			break
		}
		if len(thisVersion.GlobalHeaders) > 0 {
			used = true
			break
		}
		if len(thisVersion.GlobalHeadersRemove) > 0 {
			used = true
			break
		}
	}

	return used
}

// iterateAddHeaders is a helper functino that will iterate of a map and inject the key and value as a header in the request.
// if the key and value contain a tyk session variable reference, then it will try to inject the value
func (t *TransformHeaders) iterateAddHeaders(kv map[string]string, r *http.Request) {
	// Get session data
	ses, found := context.GetOk(r, SessionData)
	cnt, contextFound := context.GetOk(r, ContextData)
	var thisSessionState SessionState
	var contextData map[string]interface{}

	if found {
		thisSessionState = ses.(SessionState)
	}

	if contextFound {
		contextData = cnt.(map[string]interface{})
	}

	// Iterate and manage key array injection
	for nKey, nVal := range kv {
		if strings.Contains(nVal, TYK_META_LABEL) {
			// Using meta_data key
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

		} else if strings.Contains(nVal, TYK_CONTEXT_LABEL) {
			// Using context key
			if contextFound {
				metaKey := strings.Replace(nVal, TYK_CONTEXT_LABEL, "", 1)
				if contextData != nil {
					tempVal, ok := contextData[metaKey]
					if ok {
						switch tempVal.(type) {
						case string:
							nVal = tempVal.(string)
						case []string:
							nVal = strings.Join(tempVal.([]string), ",")
							// Remove empty start
							nVal = strings.TrimPrefix(nVal, ",")
						case url.Values:
							end := len(tempVal.(url.Values))
							i := 0
							nVal = ""
							for key, val := range tempVal.(url.Values) {
								nVal += key + ":" + strings.Join(val, ",")
								if i < end-1 {
									nVal += ";"
								}
								i++
							}
						default:
							log.Error("Context variable type is not supported: ", reflect.TypeOf(tempVal))
						}

						r.Header.Add(nKey, nVal)
					} else {
						log.Warning("Context Data not found for key in map: ", metaKey)
					}

				} else {
					log.Debug("Context data object is nil! Skipping.")
				}
			}

		} else {
			r.Header.Add(nKey, nVal)
		}
	}
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformHeaders) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

	// Uee the request status validator to see if it's in our cache list
	var stat RequestStatus
	var meta interface{}
	var found bool

	vInfo, versionPaths, _, _ := t.TykMiddleware.Spec.GetVersionData(r)

	// Manage global headers first - remove
	if len(vInfo.GlobalHeadersRemove) > 0 {
		for _, gdKey := range vInfo.GlobalHeadersRemove {
			log.Debug("Removing: ", gdKey)
			r.Header.Del(gdKey)
		}
	}

	// Add
	if len(vInfo.GlobalHeaders) > 0 {
		t.iterateAddHeaders(vInfo.GlobalHeaders, r)
	}

	found, meta = t.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, HeaderInjected)
	if found {
		stat = StatusHeaderInjected
	}

	if stat == StatusHeaderInjected {
		thisMeta := meta.(*tykcommon.HeaderInjectionMeta)

		for _, dKey := range thisMeta.DeleteHeaders {
			r.Header.Del(dKey)
		}

		t.iterateAddHeaders(thisMeta.AddHeaders, r)

	}

	return nil, 200
}
