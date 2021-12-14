package gateway

import (
	"errors"
	"net/http"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/request"
)

// VersionCheck will check whether the version of the requested API the request is accessing has any restrictions on URL endpoints
type VersionCheck struct {
	BaseMiddleware
	sh SuccessHandler
}

func (v *VersionCheck) Init() {
	v.sh = SuccessHandler{v.BaseMiddleware}
}

func (v *VersionCheck) Name() string {
	return "VersionCheck"
}

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
func (v *VersionCheck) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	targetVersion := v.Spec.getVersionFromRequest(r)
	if targetVersion == "" {
		targetVersion = v.Spec.VersionDefinition.Default
	}

	if v.Spec.VersionDefinition.Enabled && targetVersion != apidef.Self && targetVersion != v.Spec.VersionDefinition.Name {
		var subVersionID string
		for _, v := range v.Spec.VersionDefinition.Versions {
			if v.Name == targetVersion {
				subVersionID = v.Id
				break
			}
		}

		handler, _, found := v.Gw.findInternalHttpHandlerByNameOrID(subVersionID)
		if !found {
			return errors.New(string(VersionDoesNotExist)), http.StatusNotFound
		}

		sanitizeProxyPaths(v.Spec, r)

		handler.ServeHTTP(w, r)
		return nil, mwStatusRespond
	}

	// Check versioning, blacklist, whitelist and ignored status
	requestValid, stat := v.Spec.RequestValid(r)
	if !requestValid {
		// Fire a versioning failure event
		v.FireEvent(EventVersionFailure, EventVersionFailureMeta{
			EventMetaDefault: EventMetaDefault{
				Message:            "Attempted access to disallowed version / path.",
				OriginatingRequest: EncodeRequestToEvent(r),
			},
			Path:   r.URL.Path,
			Origin: request.RealIP(r),
			Reason: string(stat),
		})
		return errors.New(string(stat)), http.StatusForbidden
	}

	versionInfo, _ := v.Spec.Version(r)
	versionPaths := v.Spec.RxPaths[versionInfo.Name]
	whiteListStatus := v.Spec.WhiteListEnabled[versionInfo.Name]

	// We handle redirects before ignores in case we aren't using a whitelist
	if stat == StatusRedirectFlowByReply {
		_, meta := v.Spec.URLAllowedAndIgnored(r, versionPaths, whiteListStatus)
		v.DoMockReply(w, meta)
		return nil, mwStatusRespond
	}

	if expTime := versionInfo.ExpiryTime(); !expTime.IsZero() {
		w.Header().Set("x-tyk-api-expires", expTime.Format(time.RFC1123))
	}

	if stat == StatusOkAndIgnore {
		ctxSetRequestStatus(r, stat)
	}

	return nil, http.StatusOK
}
