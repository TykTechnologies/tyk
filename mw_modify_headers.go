package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type TransformHeaders struct {
	BaseMiddleware
}

const (
	metaLabel    = "$tyk_meta."
	contextLabel = "$tyk_context."
)

func (t *TransformHeaders) Name() string {
	return "TransformHeaders"
}

func (t *TransformHeaders) EnabledForSpec() bool {
	for _, version := range t.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.TransformHeader) > 0 ||
			len(version.GlobalHeaders) > 0 ||
			len(version.GlobalHeadersRemove) > 0 {
			return true
		}
	}
	return false
}

// iterateAddHeaders is a helper functino that will iterate of a map and inject the key and value as a header in the request.
// if the key and value contain a tyk session variable reference, then it will try to inject the value
func (t *TransformHeaders) iterateAddHeaders(kv map[string]string, r *http.Request) {
	// Get session data
	session := ctxGetSession(r)

	contextData := ctxGetData(r)

	// Iterate and manage key array injection
	for nKey, nVal := range kv {
		if strings.Contains(nVal, metaLabel) {
			// Using meta_data key
			if session != nil {
				metaKey := strings.Replace(nVal, metaLabel, "", 1)
				tempVal, ok := session.MetaData[metaKey]
				if ok {
					// TODO: do a better job than fmt's %v
					nVal = fmt.Sprintf("%v", tempVal)
					r.Header.Set(nKey, nVal)
				} else {
					log.Warning("Session Meta Data not found for key in map: ", metaKey)
				}
			}

		} else if strings.Contains(nVal, contextLabel) {
			// Using context key
			if contextData != nil {
				metaKey := strings.Replace(nVal, contextLabel, "", 1)
				val, ok := contextData[metaKey]
				if ok {
					r.Header.Set(nKey, valToStr(val))
				} else {
					log.Warning("Context Data not found for key in map: ", metaKey)
				}
			}

		} else {
			r.Header.Set(nKey, nVal)
		}
	}
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformHeaders) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	vInfo, versionPaths, _, _ := t.Spec.Version(r)

	// Manage global headers first - remove
	for _, gdKey := range vInfo.GlobalHeadersRemove {
		log.Debug("Removing: ", gdKey)
		r.Header.Del(gdKey)
	}

	// Add
	if len(vInfo.GlobalHeaders) > 0 {
		t.iterateAddHeaders(vInfo.GlobalHeaders, r)
	}

	found, meta := t.Spec.CheckSpecMatchesStatus(r, versionPaths, HeaderInjected)
	if found {
		hmeta := meta.(*apidef.HeaderInjectionMeta)
		for _, dKey := range hmeta.DeleteHeaders {
			r.Header.Del(dKey)
		}
		t.iterateAddHeaders(hmeta.AddHeaders, r)
	}

	return nil, 200
}
