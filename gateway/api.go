// Tyk Gateway API
//
// The code below describes the Tyk Gateway API
// Version: 2.8.0
//
//	Schemes: https, http
//	Host: localhost
//	BasePath: /tyk/
//
//	Consumes:
//	- application/json
//
//	Produces:
//	- application/json
//
//	Security:
//	- api_key:
//
//	SecurityDefinitions:
//	api_key:
//	     type: apiKey
//	     name: X-Tyk-Authorization
//	     in: header
//
// swagger:meta
package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	gql "github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	gqlv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/internal/sanitize"
	"github.com/TykTechnologies/tyk/internal/uuid"
	lib "github.com/TykTechnologies/tyk/lib/apidef"
	"github.com/TykTechnologies/tyk/pkg/controlplane/keys"
	"github.com/TykTechnologies/tyk/pkg/controlplane/oauth"
	"github.com/TykTechnologies/tyk/pkg/identifier"
	"github.com/TykTechnologies/tyk/pkg/osutil"
	"github.com/TykTechnologies/tyk/pkg/schema"
	"github.com/TykTechnologies/tyk/user"
)

const (
	oAuthClientTokensKeyPattern = "oauth-data.*oauth-client-tokens.*"
	// KeyListingWorkerCountCap 350 is based on the average of 10000 keys with minor contingency
	KeyListingWorkerCountCap      = 350
	KeyListingWorkerEntriesPerKey = 100
	errInvalidAPIID               = "Invalid API ID"
	errInvalidAPIIDFmt            = errInvalidAPIID + " %q: %v"
)

var (
	ErrRequestMalformed = errors.New("request malformed")
)

// apiModifyKeySuccess represents when a Key modification was successful
//
// swagger:model apiModifyKeySuccess
type apiModifyKeySuccess struct {
	// in:body
	Key     string `json:"key"`
	Status  string `json:"status"`
	Action  string `json:"action"`
	KeyHash string `json:"key_hash,omitempty"`
}

// apiStatusMessage represents an API status message
//
// swagger:model apiStatusMessage
type apiStatusMessage struct {
	Status string `json:"status"`
	// Response details
	Message string `json:"message"`
}

func apiOk(msg string) apiStatusMessage {
	return apiStatusMessage{"ok", msg}
}

func apiError(msg string) apiStatusMessage {
	return apiStatusMessage{"error", msg}
}

// validateMtlsStaticCertificateBindings validates that all certificate IDs in the
// mtls_static_certificate_bindings array exist in the certificate manager.
// Returns an error with the specific certificate ID if validation fails.
func (gw *Gateway) validateMtlsStaticCertificateBindings(certIDs []string, orgID string) error {
	return gw.controlPlaneKeys().ValidateMtlsStaticCertificateBindings(certIDs, orgID)
}

// getNewCertIDs returns only the certificate IDs that are in newCerts but not in originalCerts.
// Used for optimizing updates to only validate newly added certificates.
func getNewCertIDs(originalCerts, newCerts []string) []string {
	return keys.NewCertIDs(originalCerts, newCerts)
}

// paginationStatus provides more information about a paginated data set
type paginationStatus = oauth.PaginationStatus

type paginatedOAuthClientTokens = oauth.PaginatedClientTokens

type VersionMetas struct {
	Status string        `json:"status"`
	Metas  []VersionMeta `json:"apis"`
}

type VersionMeta struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	VersionName      string `json:"versionName"`
	Internal         bool   `json:"internal"`
	ExpirationDate   string `json:"expirationDate"`
	IsDefaultVersion bool   `json:"isDefaultVersion"`
}

func doJSONWrite(w http.ResponseWriter, code int, obj interface{}) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(code)

	var err error
	if bodyBytes, ok := obj.([]byte); ok {
		_, err = w.Write(bodyBytes)
	} else {
		err = json.NewEncoder(w).Encode(obj)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if code != http.StatusOK {
		job := instrument.NewJob("SystemAPIError")
		job.Event(strconv.Itoa(code))
	}
}

func doJSONExport(w http.ResponseWriter, code int, obj interface{}, fileName string) {

	if code != http.StatusOK {
		doJSONWrite(w, code, obj)
		return
	}

	stream, err := json.MarshalIndent(obj, "", "  ")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment;filename=%q", fileName))
	w.WriteHeader(code)
	_, err = w.Write(stream)

	if err != nil {
		job := instrument.NewJob("SystemAPIError")
		job.Event(err.Error())
	}

}

type MethodNotAllowedHandler struct{}

func (m MethodNotAllowedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	doJSONWrite(w, http.StatusMethodNotAllowed, apiError("Method not supported"))
}

func addSecureAndCacheHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Setting OWASP Secure Headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

		// Avoid Caching of tokens
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next(w, r)
	}
}

func allowMethods(next http.HandlerFunc, methods ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, method := range methods {
			if r.Method == method {
				next(w, r)
				return
			}
		}
		doJSONWrite(w, http.StatusMethodNotAllowed, apiError("Method not supported"))
	}
}

func (gw *Gateway) getSpecForOrg(orgID string) *APISpec {
	gw.apisMu.RLock()
	defer gw.apisMu.RUnlock()
	for _, v := range gw.apisByID {
		if v.OrgID == orgID {
			return v
		}
	}

	// If we can't find a spec, it doesn't matter, because we default to Redis anyway, grab whatever you can find
	for _, v := range gw.apisByID {
		return v
	}
	return nil
}

func (gw *Gateway) getApisIdsForOrg(orgID string) []string {
	result := []string{}

	showAll := orgID == ""
	gw.apisMu.RLock()
	defer gw.apisMu.RUnlock()
	for _, v := range gw.apisByID {
		if v.OrgID == orgID || showAll {
			result = append(result, v.APIID)
		}
	}

	return result
}

// GetApiSpecsFromAccessRights from the session.AccessRights returns the collection of api specs
func (gw *Gateway) GetApiSpecsFromAccessRights(sess *user.SessionState) []*APISpec {
	var apis []*APISpec
	if sess != nil && len(sess.AccessRights) > 0 {
		for apiID := range sess.AccessRights {
			spec := gw.getApiSpec(apiID)
			if spec != nil {
				apis = append(apis, spec)
			}
		}
	}

	return apis
}

// ApplyLifetime calculates the lifetime for the key. It considers the access rights and the bigger lifetime will be used
func (gw *Gateway) ApplyLifetime(sess *user.SessionState, specs ...*APISpec) int64 {
	infos := make([]*keys.APIInfo, 0, len(specs))
	for _, spec := range specs {
		if spec != nil {
			info := apiInfoFromSpec(spec)
			infos = append(infos, &info)
		}
	}
	return gw.controlPlaneKeys().ApplyLifetime(sess, infos...)
}

func resetAPILimits(accessRights map[string]user.AccessDefinition) {
	keys.ResetAPILimits(accessRights)
}

func (gw *Gateway) setBasicAuthSessionPassword(session *user.SessionState) {
	gw.controlPlaneKeys().SetBasicAuthSessionPassword(session)
}

func (gw *Gateway) basicAuthHashAlgo() string {
	return gw.controlPlaneKeys().BasicAuthHashAlgo()
}

func (gw *Gateway) handleAddOrUpdate(keyName string, r *http.Request, isHashed bool) (interface{}, int) {
	suppressReset := r.URL.Query().Get("suppress_reset") == "1"

	// decode payload
	newSession := &user.SessionState{}

	contents, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewReader(contents))

	if err := json.Unmarshal(contents, newSession); err != nil {
		log.Error("Couldn't decode new session object: ", err)
		return apiError("Request malformed"), http.StatusBadRequest
	}

	res, err := gw.controlPlaneKeys().CreateOrUpdate(keyName, newSession, keys.WriteOptions{
		IsPut:         r.Method == http.MethodPut,
		IsHashed:      isHashed,
		SuppressReset: suppressReset,
	})
	if err != nil {
		return cpResponse(nil, err)
	}

	event := EventTokenUpdated
	if r.Method == http.MethodPost {
		event = EventTokenCreated
	}
	gw.FireSystemEvent(event, EventTokenMeta{
		EventMetaDefault: EventMetaDefault{Message: "Key modified."},
		Org:              newSession.OrgID,
		Key:              res.StoredKey,
	})

	return res, http.StatusOK
}

func (gw *Gateway) handleGetDetail(sessionKey, apiID, orgID string, byHash bool) (interface{}, int) {
	return cpResponse(gw.controlPlaneKeys().Detail(sessionKey, apiID, orgID, byHash))
}

// apiAllKeys represents a list of keys in the memory store
// swagger:model
type apiAllKeys struct {
	APIKeys []string `json:"keys"`
}

// handleGetAllKeys retrieves keys and filters them by API ID using a Worker Pool.
func (gw *Gateway) handleGetAllKeys(c context.Context, filter string, apiID string, hashed bool) (interface{}, int) {
	list, err := gw.controlPlaneKeys().List(c, filter, apiID, hashed)
	if err != nil {
		return cpResponse(nil, err)
	}
	return apiAllKeys{list}, http.StatusOK
}

// filterKeysByAPIID handles the concurrent processing of key permissions

// getAllSessionKeys handles the retrieval of raw keys from the session manager,
// including the legacy base64 filter logic.

// keyHasAccess checks if a specific key has access to the requested API ID.

// feedKeyListingWorkers pushes keys into the job channel while filtering out internal system keys.

func (gw *Gateway) handleAddKey(keyName, sessionString, orgId string) {
	sess := &user.SessionState{}
	err := json.Unmarshal([]byte(sessionString), sess)
	if err != nil {
		log.WithError(err).WithField("keyName", keyName).Error("Failed to unmarshal session state during key update")
		return
	}
	sess.LastUpdated = strconv.Itoa(int(time.Now().Unix()))

	if sess.OrgID != orgId {
		return
	}

	lifetime := gw.ApplyLifetime(sess, nil)
	err = gw.GlobalSessionManager.UpdateSession(keyName, sess, lifetime, gw.GetConfig().HashKeys)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    gw.obfuscateKey(keyName),
			"status": "fail",
			"err":    err,
		}).Error("Failed to update key.")
		return
	}
	log.WithFields(logrus.Fields{
		"prefix": "RPC",
		"key":    gw.obfuscateKey(keyName),
		"status": "ok",
	}).Info("Updated key in slave storage.")
}

func (gw *Gateway) handleDeleteKey(keyName, orgID, apiID string, resetQuota bool) (interface{}, int) {
	res, err := gw.controlPlaneKeys().Delete(keyName, orgID, apiID, resetQuota)
	if err != nil {
		return cpResponse(nil, err)
	}
	if res == nil {
		// removed across all APIs
		return nil, http.StatusOK
	}

	gw.FireSystemEvent(EventTokenDeleted, EventTokenMeta{
		EventMetaDefault: EventMetaDefault{Message: "Key deleted."},
		Org:              orgID,
		Key:              res.Key,
	})

	return res, http.StatusOK
}

// handleDeleteHashedKeyWithLogs is a wrapper for handleDeleteHashedKey with logs
func (gw *Gateway) handleDeleteHashedKeyWithLogs(keyName, orgID, apiID string, resetQuota bool) (interface{}, int) {
	res, code := gw.handleDeleteHashedKey(keyName, orgID, apiID, resetQuota)

	if code != http.StatusOK {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    gw.obfuscateKey(keyName),
			"status": "fail",
		}).Error(res)
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    gw.obfuscateKey(keyName),
		"status": "ok",
	}).Info("Deleted hashed key across all APIs.")

	return res, code
}

func (gw *Gateway) handleDeleteHashedKey(keyName, orgID, apiID string, resetQuota bool) (interface{}, int) {
	res, err := gw.controlPlaneKeys().DeleteHashed(keyName, orgID, apiID, resetQuota)
	if err != nil {
		return cpResponse(nil, err)
	}
	if res == nil {
		return nil, http.StatusOK
	}
	return res, http.StatusOK
}

func (gw *Gateway) handleGlobalAddToSortedSet(keyName, value string, score float64) {
	gw.GlobalSessionManager.Store().AddToSortedSet(keyName, value, score)
}

func (gw *Gateway) handleGetSortedSetRange(keyName, scoreFrom, scoreTo string) ([]string, []float64, error) {
	return gw.GlobalSessionManager.Store().GetSortedSetRange(keyName, scoreFrom, scoreTo)
}

func (gw *Gateway) handleRemoveSortedSetRange(keyName, scoreFrom, scoreTo string) error {
	return gw.GlobalSessionManager.Store().RemoveSortedSetRange(keyName, scoreFrom, scoreTo)
}

func (gw *Gateway) handleGetPolicy(polID string) (interface{}, int) {
	if pol, ok := gw.policies.PolicyByID(model.NonScopedLastInsertedPolicyId(polID)); ok && pol.ID != "" {
		return pol, http.StatusOK
	}

	log.WithFields(logrus.Fields{
		"prefix": "policy",
		"polID":  polID,
	}).Error("Policy doesn't exist.")
	return apiError("Policy not found"), http.StatusNotFound
}

func (gw *Gateway) handleGetPolicyList() (interface{}, int) {
	return gw.policies.AsSlice(), http.StatusOK
}

func (gw *Gateway) newPolicyPathRoot() (*osutil.Root, error) {
	policyPath := gw.GetConfig().Policies.PolicyPath

	if policyPath == "" {
		policyPath = "."
	}

	return osutil.NewRoot(policyPath)
}

func (gw *Gateway) handleAddOrUpdatePolicy(polID string, r *http.Request) (interface{}, int) {
	if gw.GetConfig().Policies.PolicySource == "service" {
		log.Error("Rejected new policy due to PolicySource = service")
		return apiError("Due to enabled service policy source, please use the Dashboard API"), http.StatusInternalServerError
	}

	newPol := &user.Policy{}
	if err := json.NewDecoder(r.Body).Decode(newPol); err != nil {
		log.Error("Couldn't decode new policy object: ", err)
		return apiError("Request malformed"), http.StatusBadRequest
	}

	if err := gw.validator.Validate(identifier.CustomPolicyId(newPol.ID)); err != nil {
		log.WithField("id", newPol.ID).WithError(err).Error("Failed to validate policy ID")
		return apiError(identifier.ErrInvalidCustomPolicyId.Error()), http.StatusBadRequest
	}

	if polID != "" && newPol.ID != polID && r.Method == http.MethodPut {
		log.Error("PUT operation on different IDs")
		return apiError("Request ID does not match that in policy! For Update operations these must match."), http.StatusBadRequest
	}

	if !model.EnsurePolicyId(newPol) {
		const errMsg = "Unable to create policy without id."
		log.Error(errMsg)
		return apiError(errMsg), http.StatusBadRequest
	}

	if err := gw.validateMCPFieldsInAccessRights(newPol.AccessRights); err != nil {
		log.Error(err)
		return apiError(err.Error()), http.StatusBadRequest
	}

	if err := gw.validateNonMCPFieldsOnMCPProxy(newPol.AccessRights); err != nil {
		log.Error(err)
		return apiError(err.Error()), http.StatusBadRequest
	}

	if err := validateAccessConditions(newPol.AccessRights); err != nil {
		log.Error(err)
		return apiError(err.Error()), http.StatusBadRequest
	}

	root, err := gw.newPolicyPathRoot()
	if err != nil {
		log.WithError(err).Error("Unable to access the policy storage root path.")
		return apiError("Unable to access policy storage."), http.StatusInternalServerError
	}

	asByte, err := json.MarshalIndent(newPol, "", "  ")
	if err != nil {
		log.Error("Marshalling of policy failed: ", err)
		return apiError("Marshalling failed"), http.StatusInternalServerError
	}

	if err := root.WriteFile(newPol.ID+".json", asByte, 0644); err != nil {
		log.Error("Failed to create file! - ", err)
		return apiError("Failed to create file!"), http.StatusInternalServerError
	}

	action := "modified"
	if r.Method == http.MethodPost {
		action = "added"
	}

	response := apiModifyKeySuccess{
		Key:    newPol.ID,
		Status: "ok",
		Action: action,
	}

	return response, http.StatusOK
}

func (gw *Gateway) handleDeletePolicy(polID string) (interface{}, int) {
	root, err := gw.newPolicyPathRoot()

	if err != nil {
		log.WithError(err).Error("Unable to create policy root.")
		return apiError("Delete failed"), http.StatusInternalServerError
	}

	defFilePath := polID + ".json"

	// If it exists, delete it
	if _, err := root.Stat(defFilePath); err != nil {
		log.Warningf("Error describing named file: %v ", err)
		return apiError("Delete failed"), http.StatusInternalServerError
	}

	if err := root.Remove(defFilePath); err != nil {
		log.Warningf("Delete failed: %v", err)
		return apiError("Delete failed"), http.StatusInternalServerError
	}

	response := apiModifyKeySuccess{
		Key:    polID,
		Status: "ok",
		Action: "deleted",
	}

	return response, http.StatusOK
}

func (gw *Gateway) handleGetAPIList(r *http.Request) (interface{}, int) {
	includeTypes := r.URL.Query().Get("include_types")

	gw.apisMu.RLock()
	defer gw.apisMu.RUnlock()
	apiIDList := make([]*apidef.APIDefinition, 0, len(gw.apisByID))

	for _, apiSpec := range gw.apisByID {
		if shouldIncludeAPI(apiSpec, includeTypes) {
			apiIDList = append(apiIDList, apiSpec.APIDefinition)
		}
	}
	return apiIDList, http.StatusOK
}

// shouldIncludeAPI checks if an API should be included in the listing.
// MCP APIs are only included if explicitly requested in includeTypes.
func shouldIncludeAPI(apiSpec *APISpec, includeTypes string) bool {
	if !apiSpec.IsMCP() {
		return true
	}
	for _, t := range strings.Split(includeTypes, ",") {
		if strings.TrimSpace(t) == apidef.AppProtocolMCP {
			return true
		}
	}
	return false
}

func (gw *Gateway) handleGetAPIListOAS(modePublic bool) (interface{}, int) {
	return gw.handleGetOASList(isOASNotMCP, modePublic)
}

func (gw *Gateway) handleGetAPI(apiID string, oasEndpoint bool) (interface{}, int) {
	if spec := gw.getApiSpec(apiID); spec != nil {
		if oasEndpoint && spec.IsOAS {
			spec.OAS.Fill(*spec.APIDefinition)
			return &spec.OAS, http.StatusOK
		} else if oasEndpoint && !spec.IsOAS {
			return apiError(apidef.ErrOASGetForOldAPI.Error()), http.StatusBadRequest
		}

		return spec.APIDefinition, http.StatusOK
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  fmt.Sprintf("%q", apiID),
	}).Error("API doesn't exist.")

	return apiError(apidef.ErrAPINotFound.Error()), http.StatusNotFound
}

func (gw *Gateway) handleGetAPIOAS(apiID string, modePublic bool) (interface{}, int) {
	gw.apisMu.RLock()
	defer gw.apisMu.RUnlock()

	obj, code := gw.handleGetAPI(apiID, true)
	if apiOAS, ok := obj.(*oas.OAS); ok {
		// We have to operate on oas clone in order to preserve original state after any manipulations on schema.
		oasClone, _ := apiOAS.Clone() // nolint:errcheck
		if modePublic {
			oasClone.RemoveTykExtension()
		}

		visitor := schema.NewVisitor()
		visitor.AddSchemaManipulation(schema.RestoreUnicodeEscapesFromRE2Manipulation)
		visitor.ProcessOAS(oasClone)

		obj = oasClone
	}

	return obj, code
}

func (gw *Gateway) handleAddApi(r *http.Request, fs afero.Fs, oasEndpoint bool) (interface{}, int) {
	var (
		newDef apidef.APIDefinition
		oasObj oas.OAS
	)

	versionParams := lib.NewVersionQueryParameters(r.URL.Query())
	err := versionParams.Validate(func() (bool, string) {
		baseApiID := versionParams.Get(lib.BaseAPIID)
		baseApi := gw.getApiSpec(baseApiID)
		if baseApi != nil {
			return true, baseApi.VersionDefinition.Name
		}

		return false, ""
	})

	if err != nil {
		// https://tyktech.atlassian.net/browse/TT-7523?focusedCommentId=100547
		// Sadly we are averse to changing (incorrect) HTTP error codes, because these could be considered breaking changes by some of our clients.
		// Please return HTTP 422 here, because currently the request doesn’t generate an error.
		if errors.Is(err, lib.ErrNewVersionRequired) {
			return apiError(err.Error()), http.StatusUnprocessableEntity
		}

		return apiError(err.Error()), http.StatusBadRequest
	}

	if oasEndpoint {
		if err := json.NewDecoder(r.Body).Decode(&oasObj); err != nil {
			log.Error("Couldn't decode new OAS object: ", err)
			return apiError("Request malformed"), http.StatusBadRequest
		}

		oasObj.ExtractTo(&newDef)
	} else {
		if err := json.NewDecoder(r.Body).Decode(&newDef); err != nil {
			log.Error("Couldn't decode new API Definition object: ", err)
			return apiError("Request malformed"), http.StatusBadRequest
		}
	}

	if validationErr := validateAPIDef(&newDef); validationErr != nil {
		return *validationErr, http.StatusBadRequest
	}

	if newDef.APIID == "" {
		newDef.GenerateAPIID()
	}

	if err := gw.validator.Validate(identifier.CustomApiId(newDef.APIID)); err != nil {
		log.WithField("api_id", newDef.APIID).WithError(err).Error("Failed to validate API ID")
		return apiError(identifier.ErrInvalidCustomApiId.Error()), http.StatusBadRequest
	}

	if err := sanitize.ValidatePathComponent(newDef.APIID); err != nil {
		log.Errorf(errInvalidAPIIDFmt, newDef.APIID, err)
		return apiError(errInvalidAPIID), http.StatusBadRequest
	}

	if oasEndpoint {
		versioningParams := extractVersioningParams(
			versionParams.Get(lib.BaseAPIID),
			versionParams.Get(lib.NewVersionName),
		)

		if err := gw.handleOASServersForNewAPI(&newDef, &oasObj, versioningParams); err != nil {
			return apiError(err.Error()), http.StatusBadRequest
		}

		newDef.IsOAS = true
		oasObj.GetTykExtension().Info.ID = newDef.APIID
		if errMsg, errCode := gw.validatePairedMCPAdapterUpstream(r, &oasObj); errMsg != "" {
			return apiError(errMsg), errCode
		}

		err, errCode := gw.writeOASAndAPIDefToFile(fs, &newDef, &oasObj)
		if err != nil {
			return apiError(err.Error()), errCode
		}

	} else {
		newDef.IsOAS = false

		err, errCode := gw.writeToFile(fs, newDef, newDef.APIID)
		if err != nil {
			return apiError(err.Error()), errCode
		}
	}

	if !versionParams.IsEmpty(lib.BaseAPIID) {
		baseAPIID := versionParams.Get(lib.BaseAPIID)
		if err := gw.updateBaseAPIWithNewVersion(baseAPIID, versionParams, newDef.APIID, fs); err != nil {
			log.WithError(err).Error("Failed to update base API")
		}
	}

	return buildSuccessResponse(newDef.APIID, "added")
}

func (gw *Gateway) handleUpdateApi(apiID string, r *http.Request, fs afero.Fs, oasEndpoint bool) (interface{}, int) {
	if err := sanitize.ValidatePathComponent(apiID); err != nil {
		log.Errorf(errInvalidAPIIDFmt, apiID, err)
		return apiError(errInvalidAPIID), http.StatusBadRequest
	}

	spec := gw.getApiSpec(apiID)
	if resp, code := validateSpecExists(spec); resp != nil {
		return resp, code
	}

	var (
		newDef apidef.APIDefinition
		oasObj oas.OAS
	)

	if oasEndpoint {
		if !spec.IsOAS {
			return apiError(apidef.ErrAPINotMigrated.Error()), http.StatusBadRequest
		}

		if err := json.NewDecoder(r.Body).Decode(&oasObj); err != nil {
			log.Error("Couldn't decode new OAS object: ", err)
			return apiError("Request malformed"), http.StatusBadRequest
		}

		oasObj.ExtractTo(&newDef)
	} else {
		if spec.IsOAS {
			return apiError(apidef.ErrClassicAPIExpected.Error()), http.StatusBadRequest
		}

		if err := json.NewDecoder(r.Body).Decode(&newDef); err != nil {
			log.Error("Couldn't decode new API Definition object: ", err)
			return apiError("Request malformed"), http.StatusBadRequest
		}

	}

	if resp, code := validateAPIIDMatch(apiID, newDef.APIID); resp != nil {
		return resp, code
	}

	if err := gw.validator.Validate(identifier.CustomApiId(newDef.APIID)); err != nil {
		log.WithField("api_id", newDef.APIID).WithError(err).Error("Failed to validate API ID")
		return apiError(identifier.ErrInvalidCustomApiId.Error()), http.StatusBadRequest
	}

	if validationErr := validateAPIDef(&newDef); validationErr != nil {
		return *validationErr, http.StatusBadRequest
	}

	if oasEndpoint && spec.IsOAS {
		// Handle OAS server regeneration and cascade updates for API update
		if err := gw.handleOASServersForUpdate(spec, &newDef, &oasObj); err != nil {
			return apiError(err.Error()), http.StatusBadRequest
		}

		newDef.IsOAS = true
		if errMsg, errCode := gw.validatePairedMCPAdapterUpstream(r, &oasObj); errMsg != "" {
			return apiError(errMsg), errCode
		}

		err, errCode := gw.writeOASAndAPIDefToFile(fs, &newDef, &oasObj)
		if err != nil {
			return apiError(err.Error()), errCode
		}

	} else if !oasEndpoint {
		newDef.IsOAS = false

		err, errCode := gw.writeToFile(fs, newDef, newDef.APIID)
		if err != nil {
			return apiError(err.Error()), errCode
		}
	}

	return buildSuccessResponse(newDef.APIID, "modified")
}

func (gw *Gateway) writeOASAndAPIDefToFile(fs afero.Fs, apiDef *apidef.APIDefinition, oasObj *oas.OAS) (err error, errCode int) {
	err, errCode = gw.writeToFile(fs, apiDef, apiDef.APIID)
	if err != nil {
		return
	}

	suffix := "-oas"
	if apiDef.IsMCPManaged() {
		suffix = "-mcp"
	}

	oasDeepCopy, _ := oasObj.Clone() // nolint:errcheck
	visitor := schema.NewVisitor()
	visitor.AddSchemaManipulation(schema.RestoreUnicodeEscapesFromRE2Manipulation)
	visitor.ProcessOAS(oasDeepCopy)

	err, errCode = gw.writeToFile(fs, oasDeepCopy, apiDef.APIID+suffix)
	if err != nil {
		return
	}

	return
}

func (gw *Gateway) writeToFile(fs afero.Fs, newDef interface{}, filename string) (err error, errCode int) {
	if err := sanitize.ValidatePathComponent(filename); err != nil {
		log.Errorf("Invalid filename %q: %v", filename, err)
		return errors.New("invalid API ID"), http.StatusBadRequest
	}

	// Create a filename
	defFilePath := filepath.Join(gw.GetConfig().AppPath, filename+".json")

	log.Infof("App path: %v", gw.GetConfig().AppPath)
	// If it exists, delete it
	if _, err := fs.Stat(defFilePath); err == nil {
		log.Warning("API Definition with this ID already exists, deleting file...")
		fs.Remove(defFilePath)
	}

	// unmarshal the object into the file
	asByte, err := json.MarshalIndent(newDef, "", "  ")
	if err != nil {
		log.Error("Marshalling of API Definition failed: ", err)
		return errors.New("marshalling failed"), http.StatusInternalServerError
	}

	if err := afero.WriteFile(fs, defFilePath, asByte, 0644); err != nil {
		log.Infof("EL file path: %v", defFilePath)
		log.Error("Failed to create file! - ", err)
		return errors.New("file object creation failed, write error"), http.StatusInternalServerError
	}

	return nil, 0
}

func (gw *Gateway) handleDeleteAPI(apiID string) (interface{}, int) {
	if err := sanitize.ValidatePathComponent(apiID); err != nil {
		log.Errorf(errInvalidAPIIDFmt, apiID, err)
		return apiError(errInvalidAPIID), http.StatusBadRequest
	}

	spec := gw.getApiSpec(apiID)
	if resp, code := validateSpecExists(spec); resp != nil {
		return resp, code
	}

	if !spec.IsMCPManaged() {
		if pairedProxyIDs := gw.pairedMCPProxyIDsReferencingRESTSource(apiID); len(pairedProxyIDs) > 0 {
			return apiError("API is referenced by paired MCP proxies: " + strings.Join(pairedProxyIDs, ", ")), http.StatusConflict
		}
	}

	fs := afero.NewOsFs()

	if spec.IsOAS {
		if err := deleteAPIFiles(apiID, "oas", gw.GetConfig().AppPath, fs); err != nil {
			log.Warning("Delete failed: ", err)
			return apiError("Delete failed"), http.StatusInternalServerError
		}
	} else {
		defFilePath := filepath.Join(gw.GetConfig().AppPath, apiID+".json")
		defFilePath = filepath.Clean(defFilePath)

		if _, err := os.Stat(defFilePath); err != nil {
			log.Warning("File does not exist! ", err)
			return apiError("Delete failed"), http.StatusInternalServerError
		}

		if err := os.Remove(defFilePath); err != nil {
			log.WithError(err).Errorf("Failed to delete API file: %s", defFilePath)
			return apiError("Delete failed"), http.StatusInternalServerError
		}
	}

	handleBaseVersionCleanup(gw, spec, apiID, fs)
	return buildSuccessResponse(apiID, "deleted")
}

func (gw *Gateway) polHandler(w http.ResponseWriter, r *http.Request) {
	polID := mux.Vars(r)["polID"]

	var obj interface{}
	var code int

	switch r.Method {
	case http.MethodGet:
		if polID != "" {
			log.Debug("Requesting policy for", polID)
			obj, code = gw.handleGetPolicy(polID)
		} else {
			log.Debug("Requesting Policy list")
			obj, code = gw.handleGetPolicyList()
		}
	case http.MethodPost:
		log.Debug("Creating new definition file")
		obj, code = gw.handleAddOrUpdatePolicy(polID, r)
	case http.MethodPut:
		if polID != "" {
			log.Debug("Updating existing Policy: ", polID)
			obj, code = gw.handleAddOrUpdatePolicy(polID, r)
		} else {
			obj, code = apiError("Must specify an apiID to update"), http.StatusBadRequest
		}
	case http.MethodDelete:
		if polID != "" {
			log.Debug("Deleting policy for: ", polID)
			obj, code = gw.handleDeletePolicy(polID)
		} else {
			obj, code = apiError("Must specify an apiID to delete"), http.StatusBadRequest
		}
	}

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) apiHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]

	var obj interface{}
	var code int

	switch r.Method {
	case http.MethodGet:
		if apiID != "" {
			log.Debugf("Requesting API definition for %q", apiID)
			obj, code = gw.handleGetAPI(apiID, false)
		} else {
			log.Debug("Requesting API list")
			obj, code = gw.handleGetAPIList(r)
		}

		if api, ok := obj.(*apidef.APIDefinition); ok {
			if api.VersionDefinition.BaseID != "" {
				w.Header().Set(apidef.HeaderBaseAPIID, api.VersionDefinition.BaseID)
			}
		}
	case http.MethodPost:
		log.Debug("Creating new definition file")
		obj, code = gw.handleAddApi(r, afero.NewOsFs(), false)
	case http.MethodPut:
		if apiID != "" {
			log.Debugf("Updating existing API: %q", apiID)
			obj, code = gw.handleUpdateApi(apiID, r, afero.NewOsFs(), false)
		} else {
			obj, code = apiError("Must specify an apiID to update"), http.StatusBadRequest
		}
	case http.MethodDelete:
		if apiID != "" {
			log.Debug("Deleting API definition for: ", apiID)
			obj, code = gw.handleDeleteAPI(apiID)
		} else {
			obj, code = apiError("Must specify an apiID to delete"), http.StatusBadRequest
		}
	}

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) apiOASGetHandler(w http.ResponseWriter, r *http.Request) {
	var (
		apiID = mux.Vars(r)["apiID"]
		obj   interface{}
		code  int
	)
	if apiID != "" {
		log.Debugf("Requesting API definition for %q", apiID)
		obj, code = gw.handleGetAPIOAS(apiID, false)
	} else {
		log.Debug("Requesting API list")
		obj, code = gw.handleGetAPIListOAS(false)
	}

	if oasAPI, ok := obj.(*oas.OAS); ok {
		gw.setBaseAPIIDHeader(w, oasAPI)
	}

	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	doJSONWrite(w, code, jsonBytes)
}

func (gw *Gateway) apiOASPostHandler(w http.ResponseWriter, r *http.Request) {
	var (
		obj  interface{}
		code int
	)

	log.Debug("Creating new definition file")
	obj, code = gw.handleAddApi(r, afero.NewOsFs(), true)

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) apiOASPutHandler(w http.ResponseWriter, r *http.Request) {
	var (
		apiID = mux.Vars(r)["apiID"]
		obj   interface{}
		code  int
	)
	if apiID != "" {
		log.Debugf("Updating existing API: %q", apiID)
		obj, code = gw.handleUpdateApi(apiID, r, afero.NewOsFs(), true)
	} else {
		obj, code = apiError("Must specify an apiID to update"), http.StatusBadRequest
	}

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) apiOASPatchHandler(w http.ResponseWriter, r *http.Request) {
	apiID := strings.TrimSpace(mux.Vars(r)["apiID"])
	if apiID == "" {
		doJSONWrite(w, http.StatusBadRequest, apiError("Must specify an apiID to patch"))
		return
	}

	existingAPISpec := gw.getApiSpec(apiID)
	if existingAPISpec == nil {
		doJSONWrite(w, http.StatusNotFound, apiError(apidef.ErrAPINotFound.Error()))
		return
	}

	if !existingAPISpec.IsOAS {
		doJSONWrite(w, http.StatusBadRequest, apiError(apidef.ErrAPINotMigrated.Error()))
		return
	}

	reqBodyInBytes, oasObj, err := extractOASObjFromReq(r.Body)

	if err != nil {
		doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
		return
	}

	tykExtensionConfigParams := oas.GetTykExtensionConfigParams(r)

	if oasObj.GetTykExtension() != nil && tykExtensionConfigParams == nil {
		r.Body = ioutil.NopCloser(bytes.NewReader(reqBodyInBytes))
		obj, code := gw.handleUpdateApi(apiID, r, afero.NewOsFs(), true)
		doJSONWrite(w, code, obj)
		return
	}

	var oasObjToPatch oas.OAS
	existingAPISpec.OAS.Fill(*existingAPISpec.APIDefinition)
	oasObjToPatch = existingAPISpec.OAS

	var tykExtToPatch *oas.XTykAPIGateway

	if oasObj.GetTykExtension() != nil {
		tykExtToPatch = oasObj.GetTykExtension()
	} else {
		tykExtToPatch = oasObjToPatch.GetTykExtension()
	}

	serverConfig := buildServerRegenerationConfig(gw.GetConfig())
	existingUserServers, err := oas.ExtractUserServers(
		oasObjToPatch.Servers,
		existingAPISpec.APIDefinition,
		nil,
		serverConfig,
		"",
	)
	if err != nil {
		doJSONWrite(w, http.StatusInternalServerError, apiError(err.Error()))
		return
	}

	patchUserServers := oasObj.Servers

	userServersToKeep := patchUserServers
	if len(patchUserServers) == 0 {
		userServersToKeep = existingUserServers
	}

	oasObj.Servers = userServersToKeep

	oasObjToPatch.T = oasObj.T

	oasObjToPatch.SetTykExtension(tykExtToPatch)

	if tykExtensionConfigParams != nil {
		err = oasObjToPatch.BuildDefaultTykExtension(*tykExtensionConfigParams, false)
		if err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}
	}
	oasObjToPatch.ImportMiddlewares(oas.TykExtensionConfigParams{})

	oasAPIInBytes, err := oasObjToPatch.MarshalJSON()
	if err != nil {
		doJSONWrite(w, http.StatusInternalServerError, apiError(err.Error()))
		return
	}

	r.Body = ioutil.NopCloser(bytes.NewReader(oasAPIInBytes))

	log.Debugf("PATCHing API: %q", apiID)
	obj, code := gw.handleUpdateApi(apiID, r, afero.NewOsFs(), true)

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) apiOASExportHandler(w http.ResponseWriter, r *http.Request) {
	const (
		baseFileName       = "TykOasApiDef"
		baseFileNamePublic = "oas"
		fileTypeJSON       = "json"
	)
	var (
		apiID       = mux.Vars(r)["apiID"]
		fileName    = baseFileName
		scopePublic = r.URL.Query().Get("mode") == "public"
		obj         interface{}
		code        int
	)

	if scopePublic {
		fileName = baseFileNamePublic
	}

	if apiID != "" {
		log.Debugf("Requesting API definition for %q", apiID)
		obj, code = gw.handleGetAPIOAS(apiID, scopePublic)
		fileName += "-" + apiID
	} else {
		log.Debug("Requesting API list")
		obj, code = gw.handleGetAPIListOAS(scopePublic)
	}

	doJSONExport(w, code, obj, fmt.Sprintf("%s.%s", fileName, fileTypeJSON))
}

func (gw *Gateway) keyHandler(w http.ResponseWriter, r *http.Request) {
	keyName := mux.Vars(r)["keyName"]
	apiID := r.URL.Query().Get("api_id")
	isHashed := r.URL.Query().Get("hashed") != ""
	isUserName := r.URL.Query().Get("username") == "true"
	orgID := r.URL.Query().Get("org_id")

	// check if passed key is user name and convert it to real key with respect to current hashing algorithm
	origKeyName := keyName
	gwConfig := gw.GetConfig()

	if r.Method != http.MethodPost && isUserName && !gwConfig.DisableKeyActionsByUsername {
		keyName = gw.generateToken(orgID, keyName)
	}

	var obj interface{}
	var code int
	hashKeyFunction := gwConfig.HashKeyFunction

	switch r.Method {
	case http.MethodPost:
		obj, code = gw.handleAddOrUpdate(keyName, r, isHashed)
	case http.MethodPut:
		obj, code = gw.handleAddOrUpdate(keyName, r, isHashed)
		if code != http.StatusOK && hashKeyFunction != "" {
			// try to use legacy key format
			obj, code = gw.handleAddOrUpdate(origKeyName, r, isHashed)
		}
	case http.MethodGet:
		if keyName != "" {
			// Return single key detail
			obj, code = gw.handleGetDetail(keyName, apiID, orgID, isHashed)
			if code != http.StatusOK && hashKeyFunction != "" {
				// try to use legacy key format
				obj, code = gw.handleGetDetail(origKeyName, apiID, orgID, isHashed)
			}
		} else {
			// Return list of keys
			if gwConfig.HashKeys {
				// get all keys is disabled by default
				if !gwConfig.EnableHashedKeysListing {
					doJSONWrite(w, http.StatusNotFound, apiError("Hashed key listing is disabled in config (enable_hashed_keys_listing)"))
					return
				}
				obj, code = gw.handleGetAllKeys(r.Context(), "", apiID, true)
			} else {
				filter := r.URL.Query().Get("filter")
				if apiID != "" && filter == "" {
					doJSONWrite(w, http.StatusBadRequest, apiError("The 'filter' parameter (Org ID) is required when filtering by 'api_id' in legacy mode"))
					return
				}
				obj, code = gw.handleGetAllKeys(r.Context(), filter, apiID, false)
			}
		}

	case http.MethodDelete:
		// Remove a key
		if !isHashed {
			obj, code = gw.handleDeleteKey(keyName, orgID, apiID, true)
		} else {
			obj, code = gw.handleDeleteHashedKeyWithLogs(keyName, orgID, apiID, true)
		}
		if code != http.StatusOK && hashKeyFunction != "" {
			// try to use legacy key format
			if !isHashed {
				obj, code = gw.handleDeleteKey(origKeyName, orgID, apiID, true)
			} else {
				obj, code = gw.handleDeleteHashedKeyWithLogs(origKeyName, orgID, apiID, true)
			}
		}
	}

	doJSONWrite(w, code, obj)
}

type PolicyUpdateObj struct {
	Policy        string   `json:"policy"`
	ApplyPolicies []string `json:"apply_policies"`
}

func (gw *Gateway) policyUpdateHandler(w http.ResponseWriter, r *http.Request) {
	log.Warning("Hashed key change request detected!")

	var policRecord PolicyUpdateObj
	if err := json.NewDecoder(r.Body).Decode(&policRecord); err != nil {
		doJSONWrite(w, http.StatusBadRequest, apiError("Couldn't decode instruction"))
		return
	}

	if policRecord.Policy != "" {
		policRecord.ApplyPolicies = append(policRecord.ApplyPolicies, policRecord.Policy)
	}

	keyName := mux.Vars(r)["keyName"]
	obj, code := gw.handleUpdateHashedKey(keyName, policRecord.ApplyPolicies)

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) handleUpdateHashedKey(keyName string, applyPolicies []string) (interface{}, int) {
	return cpResponse(gw.controlPlaneKeys().ApplyPolicyIDs(keyName, applyPolicies))
}

func (gw *Gateway) orgHandler(w http.ResponseWriter, r *http.Request) {
	orgID := mux.Vars(r)["keyName"]
	filter := r.URL.Query().Get("filter")
	var obj interface{}
	var code int

	switch r.Method {
	case "POST", "PUT":
		obj, code = gw.handleOrgAddOrUpdate(orgID, r)

	case "GET":
		if orgID != "" {
			// Return single org detail
			obj, code = gw.handleGetOrgDetail(orgID)
		} else {
			// Return list of keys
			obj, code = gw.handleGetAllOrgKeys(filter)
		}

	case "DELETE":
		// Remove a key
		obj, code = gw.handleDeleteOrgKey(orgID)
	}

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) handleOrgAddOrUpdate(orgID string, r *http.Request) (interface{}, int) {
	newSession := new(user.SessionState)

	if err := json.NewDecoder(r.Body).Decode(newSession); err != nil {
		log.Error("Couldn't decode new session object: ", err)
		return apiError("Request malformed"), http.StatusBadRequest
	}

	res, err := gw.controlPlaneOrgKeys().Set(orgID, newSession, r.Method == http.MethodPut, r.URL.Query().Get("reset_quota") == "1")
	if err != nil {
		return cpResponse(nil, err)
	}

	// identify that spec has org session
	if res.Found {
		if spec := gw.getSpecForOrg(orgID); spec != nil {
			spec.Lock()
			spec.OrgHasNoSession = false
			spec.Unlock()
		}
	}

	return res.Result, http.StatusOK
}

func (gw *Gateway) handleGetOrgDetail(orgID string) (interface{}, int) {
	return cpResponse(gw.controlPlaneOrgKeys().Get(orgID))
}

func (gw *Gateway) handleGetAllOrgKeys(filter string) (interface{}, int) {
	list, err := gw.controlPlaneOrgKeys().List(filter)
	if err != nil {
		return cpResponse(nil, err)
	}
	return apiAllKeys{list}, http.StatusOK
}

func (gw *Gateway) handleDeleteOrgKey(orgID string) (interface{}, int) {
	res, err := gw.controlPlaneOrgKeys().Delete(orgID)
	if err != nil {
		return cpResponse(nil, err)
	}

	// identify that spec has no org session
	if spec := gw.getSpecForOrg(orgID); spec != nil {
		spec.Lock()
		spec.OrgHasNoSession = true
		spec.Unlock()
	}

	return res.Result, http.StatusOK
}

func (gw *Gateway) groupResetHandler(w http.ResponseWriter, r *http.Request) {
	log.WithFields(logrus.Fields{
		"prefix": "api",
		"status": "ok",
	}).Info("Group reload accepted.")

	// Signal to the group via redis
	gw.MainNotifier.Notify(Notification{Command: NoticeGroupReload, Gw: gw})

	log.WithFields(logrus.Fields{
		"prefix": "api",
	}).Info("Reloaded URL Structure - Success")

	doJSONWrite(w, http.StatusOK, apiOk(""))
}

// resetHandler will try to queue a reload. If fn is nil and block=true
// was in the URL parameters, it will block until the reload is done.
// Otherwise, it won't block and fn will be called once the reload is
// finished.
func (gw *Gateway) resetHandler(fn func()) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var wg sync.WaitGroup

		if fn == nil && r.URL.Query().Get("block") == "true" {
			wg.Add(1)
			gw.reloadURLStructure(wg.Done)
		} else {
			gw.reloadURLStructure(fn)
		}

		log.WithFields(logrus.Fields{
			"prefix": "api",
		}).Info("Reload URL Structure - Scheduled")
		wg.Wait()
		doJSONWrite(w, http.StatusOK, apiOk(""))
	}
}

func (gw *Gateway) createKeyHandler(w http.ResponseWriter, r *http.Request) {
	newSession := new(user.SessionState)
	if err := json.NewDecoder(r.Body).Decode(newSession); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"status": "fail",
			"err":    err,
		}).Error("Key creation failed.")
		doJSONWrite(w, http.StatusInternalServerError, apiError("Unmarshalling failed"))
		return
	}

	res, err := gw.controlPlaneKeys().Create(newSession)
	if err != nil {
		obj, code := cpResponse(nil, err)
		doJSONWrite(w, code, obj)
		return
	}

	gw.FireSystemEvent(EventTokenCreated, EventTokenMeta{
		EventMetaDefault: EventMetaDefault{Message: "Key generated."},
		Org:              newSession.OrgID,
		Key:              res.Key,
	})

	doJSONWrite(w, http.StatusOK, res)
}

func (gw *Gateway) previewKeyHandler(w http.ResponseWriter, r *http.Request) {
	newSession := new(user.SessionState)

	if err := json.NewDecoder(r.Body).Decode(newSession); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"status": "fail",
			"err":    err,
		}).Error("Key creation failed.")
		doJSONWrite(w, http.StatusInternalServerError, apiError("Unmarshalling failed"))
		return
	}

	doJSONWrite(w, http.StatusOK, gw.controlPlaneKeys().Preview(newSession))
}

// NewClientRequest is an outward facing JSON object translated from osin OAuthClients
//
// swagger:model NewClientRequest
type NewClientRequest = oauth.ClientRequest

func (gw *Gateway) createOauthClient(w http.ResponseWriter, r *http.Request) {
	var newOauthClient NewClientRequest
	if err := json.NewDecoder(r.Body).Decode(&newOauthClient); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"status": "fail",
			"err":    err,
		}).Error("Failed to create OAuth client")
		doJSONWrite(w, http.StatusInternalServerError, apiError("Unmarshalling failed"))
		return
	}

	obj, code := cpResponse(gw.controlPlaneOAuth().CreateClient(newOauthClient))
	doJSONWrite(w, code, obj)
}

func (gw *Gateway) rotateOauthClient(keyName, apiID string) (interface{}, int) {
	return cpResponse(gw.controlPlaneOAuth().RotateClientSecret(apiID, keyName))
}

// Update Client
func (gw *Gateway) updateOauthClient(keyName, apiID string, r *http.Request) (interface{}, int) {
	var updateClientData NewClientRequest
	if err := json.NewDecoder(r.Body).Decode(&updateClientData); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"status": "fail",
			"err":    err,
		}).Error("Failed to update OAuth client")
		return apiError("Unmarshalling failed"), http.StatusInternalServerError
	}

	return cpResponse(gw.controlPlaneOAuth().UpdateClient(apiID, keyName, updateClientData))
}

func (gw *Gateway) invalidateOauthRefresh(w http.ResponseWriter, r *http.Request) {
	apiID := r.URL.Query().Get("api_id")
	keyName := mux.Vars(r)["keyName"]
	obj, code := cpResponse(gw.controlPlaneOAuth().InvalidateRefresh(apiID, keyName))
	doJSONWrite(w, code, obj)
}

func (gw *Gateway) rotateOauthClientHandler(w http.ResponseWriter, r *http.Request) {

	apiID := mux.Vars(r)["apiID"]
	keyName := mux.Vars(r)["keyName"]

	obj, code := gw.rotateOauthClient(keyName, apiID)

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) getApisForOauthApp(w http.ResponseWriter, r *http.Request) {
	appID := mux.Vars(r)["appID"]
	orgID := r.FormValue("orgID")
	doJSONWrite(w, http.StatusOK, gw.controlPlaneOAuth().APIsForClient(appID, orgID))
}

func (gw *Gateway) oAuthClientHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	keyName := mux.Vars(r)["keyName"]

	var obj interface{}
	var code int
	switch r.Method {
	case http.MethodGet:
		if keyName != "" {
			// Return single client detail
			obj, code = gw.getOauthClientDetails(keyName, apiID)
		} else {
			// Return list of keys
			obj, code = gw.getOauthClients(apiID)
		}
	case http.MethodPut:
		// Update client
		obj, code = gw.updateOauthClient(keyName, apiID, r)
	case http.MethodDelete:
		// Remove a key
		obj, code = gw.handleDeleteOAuthClient(keyName, apiID)
	}

	doJSONWrite(w, code, obj)
}

func (gw *Gateway) oAuthClientTokensHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	keyName := mux.Vars(r)["keyName"]

	if p := r.URL.Query().Get("page"); p != "" {
		page := 1

		queryPage, err := strconv.Atoi(p)
		if err == nil {
			page = queryPage
		}

		if page <= 0 {
			page = 1
		}

		obj, code := cpResponse(gw.controlPlaneOAuth().ClientTokensPage(apiID, keyName, page))
		doJSONWrite(w, code, obj)
		return
	}

	obj, code := cpResponse(gw.controlPlaneOAuth().ClientTokens(apiID, keyName))
	doJSONWrite(w, code, obj)
}

// Get client details
func (gw *Gateway) getOauthClientDetails(keyName, apiID string) (interface{}, int) {
	return cpResponse(gw.controlPlaneOAuth().GetClient(apiID, keyName))
}

func (gw *Gateway) oAuthTokensHandler(w http.ResponseWriter, r *http.Request) {
	if !r.URL.Query().Has("scope") {
		doJSONWrite(w, http.StatusUnprocessableEntity, apiError("scope parameter is required"))
		return
	}

	if r.URL.Query().Get("scope") != "lapsed" {
		doJSONWrite(w, http.StatusBadRequest, apiError("unknown scope"))
		return
	}

	err := gw.purgeLapsedOAuthTokens()
	if err != nil {
		doJSONWrite(w, http.StatusInternalServerError, apiError("error purging lapsed tokens"))
		return
	}

	doJSONWrite(w, http.StatusOK, apiOk("lapsed tokens purged"))
}

// Delete Client
func (gw *Gateway) handleDeleteOAuthClient(keyName, apiID string) (interface{}, int) {
	return cpResponse(gw.controlPlaneOAuth().DeleteClient(apiID, keyName))
}

const oAuthNotPropagatedErr = "OAuth client list isn't available or hasn't been propagated yet."
const oAuthClientNotFound = "OAuth client not found"
const oauthClientIdEmpty = "client_id is required"
const oauthClientSecretEmpty = "client_secret is required"
const oauthClientSecretWrong = "client secret is wrong"
const oauthTokenEmpty = "token is required"

// List Clients
func (gw *Gateway) getOauthClients(apiID string) (interface{}, int) {
	return cpResponse(gw.controlPlaneOAuth().ListClients(apiID))
}

func (gw *Gateway) healthCheckhandler(w http.ResponseWriter, r *http.Request) {
	if !gw.GetConfig().HealthCheck.EnableHealthChecks {
		doJSONWrite(w, http.StatusBadRequest, apiError("Health checks are not enabled for this node"))
		return
	}
	apiID := r.URL.Query().Get("api_id")
	if apiID == "" {
		doJSONWrite(w, http.StatusBadRequest, apiError("missing api_id parameter"))
		return
	}
	apiSpec := gw.getApiSpec(apiID)
	if apiSpec == nil {
		doJSONWrite(w, http.StatusNotFound, apiError("API ID not found"))
		return
	}
	health, _ := apiSpec.Health.ApiHealthValues()
	doJSONWrite(w, http.StatusOK, health)
}

func userRatesCheck(w http.ResponseWriter, r *http.Request) {
	session := ctxGetSession(r)
	if session == nil {
		doJSONWrite(w, http.StatusBadRequest, apiError("Health checks are not enabled for this node"))
		return
	}

	returnSession := PublicSession{}
	returnSession.Quota.QuotaRenews = session.QuotaRenews
	returnSession.Quota.QuotaRemaining = session.QuotaRemaining
	returnSession.Quota.QuotaMax = session.QuotaMax
	returnSession.RateLimit.Rate = session.Rate
	returnSession.RateLimit.Per = session.Per

	doJSONWrite(w, http.StatusOK, returnSession)
}

func (gw *Gateway) invalidateCacheHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]

	if ok := gw.invalidateAPICache(apiID); !ok {
		err := errors.New("scan/delete failed")
		var orgid string
		if spec := gw.getApiSpec(apiID); spec != nil {
			orgid = spec.OrgID
		}
		log.WithFields(logrus.Fields{
			"prefix":      "api",
			"api_id":      apiID,
			"status":      "fail",
			"err":         err,
			"org_id":      orgid,
			"user_id":     "system",
			"user_ip":     requestIPHops(r),
			"path":        "--",
			"server_name": "system",
		}).Error("Failed to delete cache: ", err)

		doJSONWrite(w, http.StatusInternalServerError, apiError("Cache invalidation failed"))
		return
	}

	doJSONWrite(w, http.StatusOK, apiOk("cache invalidated"))
}

func (gw *Gateway) RevokeTokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		doJSONWrite(w, http.StatusBadRequest, apiError("cannot parse form. Form malformed"))
		return
	}

	tokenTypeHint := r.PostFormValue("token_type_hint")
	token := r.PostFormValue("token")
	clientID := r.PostFormValue("client_id")
	orgID := r.PostFormValue("org_id")

	if err := gw.controlPlaneOAuth().RevokeClientToken(orgID, clientID, token, tokenTypeHint); err != nil {
		obj, code := cpResponse(nil, err)
		doJSONWrite(w, code, obj)
		return
	}
	doJSONWrite(w, http.StatusOK, apiOk("token revoked successfully"))
}

func (gw *Gateway) GetStorageForApi(apiID string) (ExtendedOsinStorageInterface, int, error) {
	st, res := gwOAuthResolver{gw}.StorageFor(apiID, false)
	switch res {
	case oauth.APINotFound:
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    "API not found",
		}).Error("Failed to retrieve OAuth client list.")
		return nil, http.StatusNotFound, errors.New(oAuthClientNotFound)
	case oauth.NoManager:
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    "API not found",
		}).Error("Failed to revoke client tokens.")
		return nil, http.StatusNotFound, errors.New(oAuthNotPropagatedErr)
	}
	return st, http.StatusOK, nil
}

func (gw *Gateway) RevokeAllTokensHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		doJSONWrite(w, http.StatusBadRequest, apiError("cannot parse form. Form malformed"))
		return
	}

	clientId := r.PostFormValue("client_id")
	clientSecret := r.PostFormValue("client_secret")
	orgId := r.PostFormValue("org_id")

	tokens, err := gw.controlPlaneOAuth().RevokeAllClientTokens(orgId, clientId, clientSecret)
	if err != nil {
		obj, code := cpResponse(nil, err)
		doJSONWrite(w, code, obj)
		return
	}

	n := Notification{
		Command: KeySpaceUpdateNotification,
		Payload: strings.Join(tokens, ","),
		Gw:      gw,
	}
	gw.MainNotifier.Notify(n)

	doJSONWrite(w, http.StatusOK, apiOk("tokens revoked successfully"))
}

func (gw *Gateway) validateOAS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqBodyInBytes, oasObj, err := extractOASObjFromReq(r.Body)

		if err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		if strings.HasSuffix(r.URL.Path, "/import") && oasObj.GetTykExtension() != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(apidef.ErrImportWithTykExtension.Error()))
			return
		}

		if (r.Method == http.MethodPost || r.Method == http.MethodPut) && !strings.HasSuffix(r.URL.Path, "/import") && oasObj.GetTykExtension() == nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(apidef.ErrPayloadWithoutTykExtension.Error()))
			return
		}

		if err = oas.ValidateOASObject(reqBodyInBytes, oasObj.OpenAPI); err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		if err = oasObj.Validate(r.Context(), oas.GetValidationOptionsFromConfig(gw.GetConfig().OAS)...); err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		r.Body = ioutil.NopCloser(bytes.NewReader(reqBodyInBytes))
		next.ServeHTTP(w, r)
	}
}

func (gw *Gateway) blockInDashboardMode(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if gw.GetConfig().UseDBAppConfigs {
			doJSONWrite(w, http.StatusInternalServerError, apiError("Due to enabled use_db_app_configs, please use the Dashboard API"))
			return
		}

		next.ServeHTTP(w, r)
	}
}

func (gw *Gateway) makeImportedOASTykAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, oasObj, err := extractOASObjFromReq(r.Body)
		if err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError("Couldn't decode OAS object"))
			return
		}

		tykExtensionConfigParams := oas.GetTykExtensionConfigParams(r)
		if tykExtensionConfigParams == nil {
			tykExtensionConfigParams = &oas.TykExtensionConfigParams{}
		}

		err = oasObj.BuildDefaultTykExtension(*tykExtensionConfigParams, true)
		if err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		oasObj.GetTykExtension().Server.ListenPath.Strip = true

		apiInBytes, err := oasObj.MarshalJSON()
		if err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		r.Body = ioutil.NopCloser(bytes.NewReader(apiInBytes))
		next.ServeHTTP(w, r)
	}
}

// ctxSetCacheOptions sets a cache key to use for the http request
func ctxSetCacheOptions(r *http.Request, options *cacheOptions) {
	setCtxValue(r, ctx.CacheOptions, options)
}

// ctxGetCacheOptions returns a cache key if we need to cache request
func ctxGetCacheOptions(r *http.Request) *cacheOptions {
	key, _ := r.Context().Value(ctx.CacheOptions).(*cacheOptions)
	return key
}

// ctxSetMatchedBinding stores the client-IdP registry binding matched for this
// request. JWTMiddleware is a single shared instance per API and its
// ProcessRequest runs concurrently, so per-request state must live on the
// context, not the middleware struct.
func ctxSetMatchedBinding(r *http.Request, b *Binding) {
	setCtxValue(r, ctx.MatchedIdPBinding, b)
}

// ctxGetMatchedBinding returns the matched binding for this request, or nil.
func ctxGetMatchedBinding(r *http.Request) *Binding {
	b, ok := r.Context().Value(ctx.MatchedIdPBinding).(*Binding)
	if !ok {
		return nil
	}
	return b
}

func ctxGetSession(r *http.Request) *user.SessionState {
	return ctx.GetSession(r)
}

func ctxSetSession(r *http.Request, s *user.SessionState, scheduleUpdate bool, hashKey bool) {
	ctx.SetSession(r, s, scheduleUpdate, hashKey)
}

func ctxGetAuthToken(r *http.Request) string {
	return ctx.GetAuthToken(r)
}

func ctxGetTrackedPath(r *http.Request) string {
	if v := r.Context().Value(ctx.TrackThisEndpoint); v != nil {
		return v.(string)
	}
	return ""
}

func ctxSetTrackedPath(r *http.Request, p string) {
	if p == "" {
		panic("setting a nil context TrackThisEndpoint")
	}
	setCtxValue(r, ctx.TrackThisEndpoint, p)
}

func ctxGetDoNotTrack(r *http.Request) bool {
	return r.Context().Value(ctx.DoNotTrackThisEndpoint) == true
}

func ctxSetDoNotTrack(r *http.Request, b bool) {
	setCtxValue(r, ctx.DoNotTrackThisEndpoint, b)
}

func ctxSetRequestStartTime(r *http.Request, t time.Time) {
	setCtxValue(r, ctx.RequestStartTime, t)
}

func ctxGetRequestStartTime(r *http.Request) time.Time {
	if v := r.Context().Value(ctx.RequestStartTime); v != nil {
		if t, ok := v.(time.Time); ok {
			return t
		}
	}
	return time.Time{}
}

func ctxSetOriginalRequestPath(r *http.Request, path string) {
	setCtxValue(r, ctx.OriginalRequestPath, path)
}

func ctxGetOriginalRequestPath(r *http.Request) string {
	if v := r.Context().Value(ctx.OriginalRequestPath); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func withOriginalPathSpanAttribute(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if originalPath := ctxGetOriginalRequestPath(r); originalPath != "" {
			span := otel.SpanFromContext(r.Context())
			span.SetAttributes(otel.OriginalPathSpanAttribute(originalPath))
		}

		next.ServeHTTP(w, r)
	})
}

func ctxGetVersionInfo(r *http.Request) *apidef.VersionInfo {
	if v := r.Context().Value(ctx.VersionData); v != nil {
		return v.(*apidef.VersionInfo)
	}
	return nil
}

func ctxSetVersionInfo(r *http.Request, v *apidef.VersionInfo) {
	setCtxValue(r, ctx.VersionData, v)
}

func ctxGetVersionName(r *http.Request) *string {
	if v := r.Context().Value(ctx.VersionName); v != nil {
		return v.(*string)
	}

	return nil
}

func ctxSetVersionName(r *http.Request, vName *string) {
	setCtxValue(r, ctx.VersionName, vName)
}

func ctxSetOrigRequestURL(r *http.Request, url *url.URL) {
	setCtxValue(r, ctx.OrigRequestURL, url)
}

func ctxGetOrigRequestURL(r *http.Request) *url.URL {
	if v := r.Context().Value(ctx.OrigRequestURL); v != nil {
		if urlVal, ok := v.(*url.URL); ok {
			return urlVal
		}
	}

	return nil
}

func ctxSetURLRewriteTarget(r *http.Request, url *url.URL) {
	setCtxValue(r, ctx.UrlRewriteTarget, url)
}

func ctxGetURLRewriteTarget(r *http.Request) *url.URL {
	if v := r.Context().Value(ctx.UrlRewriteTarget); v != nil {
		if urlVal, ok := v.(*url.URL); ok {
			return urlVal
		}
	}

	return nil
}

func ctxSetUrlRewritePath(r *http.Request, path string) {
	setCtxValue(r, ctx.UrlRewritePath, path)
}

func ctxGetUrlRewritePath(r *http.Request) string {
	if v := r.Context().Value(ctx.UrlRewritePath); v != nil {
		if strVal, ok := v.(string); ok {
			return strVal
		}
	}
	return ""
}

func ctxSetInternalRedirectTarget(r *http.Request, u *url.URL) {
	setCtxValue(r, ctx.InternalRedirectTarget, u)
}

func ctxGetInternalRedirectTarget(r *http.Request) *url.URL {
	if v := r.Context().Value(ctx.InternalRedirectTarget); v != nil {
		if val, ok := v.(*url.URL); ok {
			return val
		}
	}

	if r.URL == nil {
		return nil
	}

	clone := *r.URL
	return &clone
}

func ctxSetCheckLoopLimits(r *http.Request, b bool) {
	setCtxValue(r, ctx.CheckLoopLimits, b)
}

// Should we check Rate limits and Quotas?
func ctxCheckLimits(r *http.Request) bool {
	// Check explicit flag first - allows MCP sequential routing to opt into limits at each VEM stage
	if v := r.Context().Value(ctx.CheckLoopLimits); v != nil {
		if b, ok := v.(bool); ok {
			return b
		}
	}

	// If this is a self loop, do not need to check the limits and quotas.
	if httpctx.IsSelfLooping(r) {
		return false
	}

	// If looping disabled, allow all
	if !ctxLoopingEnabled(r) {
		return true
	}

	return false
}

func ctxSetRequestMethod(r *http.Request, path string) {
	setCtxValue(r, ctx.RequestMethod, path)
}

func ctxGetRequestMethod(r *http.Request) string {
	if v := r.Context().Value(ctx.RequestMethod); v != nil {
		if strVal, ok := v.(string); ok {
			return strVal
		}
	}
	return r.Method
}

func ctxSetTransformRequestMethod(r *http.Request, path string) {
	setCtxValue(r, ctx.TransformedRequestMethod, path)
}

func ctxGetTransformRequestMethod(r *http.Request) string {
	if v := r.Context().Value(ctx.TransformedRequestMethod); v != nil {
		if strVal, ok := v.(string); ok {
			return strVal
		}
	}
	return r.Method
}

func ctxSetGraphQLRequest(r *http.Request, gqlRequest *gql.Request) {
	setCtxValue(r, ctx.GraphQLRequest, gqlRequest)
}

func ctxGetGraphQLRequest(r *http.Request) (gqlRequest *gql.Request) {
	if v := r.Context().Value(ctx.GraphQLRequest); v != nil {
		if gqlRequest, ok := v.(*gql.Request); ok {
			return gqlRequest
		}
	}
	return nil
}

func ctxSetGraphQLRequestV2(r *http.Request, gqlRequest *gqlv2.Request) {
	setCtxValue(r, ctx.GraphQLRequest, gqlRequest)
}

func ctxGetGraphQLRequestV2(r *http.Request) (gqlRequest *gqlv2.Request) {
	if v := r.Context().Value(ctx.GraphQLRequest); v != nil {
		if gqlRequest, ok := v.(*gqlv2.Request); ok {
			return gqlRequest
		}
	}
	return nil
}

func ctxSetGraphQLIsWebSocketUpgrade(r *http.Request, isWebSocketUpgrade bool) {
	setCtxValue(r, ctx.GraphQLIsWebSocketUpgrade, isWebSocketUpgrade)
}

func ctxGetGraphQLIsWebSocketUpgrade(r *http.Request) (isWebSocketUpgrade bool) {
	if v := r.Context().Value(ctx.GraphQLIsWebSocketUpgrade); v != nil {
		if isWebSocketUpgrade, ok := v.(bool); ok {
			return isWebSocketUpgrade
		}
	}

	return false
}

func ctxGetDefaultVersion(r *http.Request) bool {
	return r.Context().Value(ctx.VersionDefault) != nil
}

func ctxSetDefaultVersion(r *http.Request) {
	setCtxValue(r, ctx.VersionDefault, true)
}

func ctxLoopingEnabled(r *http.Request) bool {
	return ctxLoopLevel(r) > 0
}

func ctxLoopLevel(r *http.Request) int {
	if v := r.Context().Value(ctx.LoopLevel); v != nil {
		if intVal, ok := v.(int); ok {
			return intVal
		}
	}

	return 0
}

func ctxSetLoopLevel(r *http.Request, value int) {
	setCtxValue(r, ctx.LoopLevel, value)
}

func ctxIncLoopLevel(r *http.Request, loopLimit int) {
	ctxSetLoopLimit(r, loopLimit)
	ctxSetLoopLevel(r, ctxLoopLevel(r)+1)
}

func ctxLoopLevelLimit(r *http.Request) int {
	if v := r.Context().Value(ctx.LoopLevelLimit); v != nil {
		if intVal, ok := v.(int); ok {
			return intVal
		}
	}

	return 0
}

func ctxSetLoopLimit(r *http.Request, limit int) {
	// Can be set only one time per request
	if ctxLoopLevelLimit(r) == 0 && limit > 0 {
		setCtxValue(r, ctx.LoopLevelLimit, limit)
	}
}

func ctxThrottleLevelLimit(r *http.Request) int {
	if v := r.Context().Value(ctx.ThrottleLevelLimit); v != nil {
		if intVal, ok := v.(int); ok {
			return intVal
		}
	}

	return 0
}

func ctxThrottleLevel(r *http.Request) int {
	if v := r.Context().Value(ctx.ThrottleLevel); v != nil {
		if intVal, ok := v.(int); ok {
			return intVal
		}
	}

	return 0
}

func ctxSetThrottleLimit(r *http.Request, limit int) {
	// Can be set only one time per request
	if ctxThrottleLevelLimit(r) == 0 && limit > 0 {
		setCtxValue(r, ctx.ThrottleLevelLimit, limit)
	}
}

func ctxSetThrottleLevel(r *http.Request, value int) {
	setCtxValue(r, ctx.ThrottleLevel, value)
}

func ctxIncThrottleLevel(r *http.Request, throttleLimit int) {
	ctxSetThrottleLimit(r, throttleLimit)
	ctxSetThrottleLevel(r, ctxThrottleLevel(r)+1)
}

func ctxSetSpanAttributes(r *http.Request, mwName string, attrs ...otel.SpanAttribute) {
	if len(attrs) > 0 {
		setCtxValue(r, mwName, attrs)
	}
}

func ctxGetSpanAttributes(r *http.Request, mwName string) (attrs []otel.SpanAttribute) {
	if v := r.Context().Value(mwName); v != nil {
		got, ok := v.([]otel.SpanAttribute)
		if ok {
			attrs = got
		}
	}
	return
}

func ctxSetRequestStatus(r *http.Request, stat RequestStatus) {
	setCtxValue(r, ctx.RequestStatus, stat)
}

func ctxGetRequestStatus(r *http.Request) (stat RequestStatus) {
	if v := r.Context().Value(ctx.RequestStatus); v != nil {
		stat = v.(RequestStatus)
	}
	return
}

func ctxSetMCPMethod(r *http.Request, method string) {
	setCtxValue(r, ctx.MCPMethod, method)
}

func ctxGetMCPMethod(r *http.Request) string {
	return ctx.GetMCPMethod(r)
}

func ctxSetMCPPrimitiveType(r *http.Request, primitiveType string) {
	setCtxValue(r, ctx.MCPPrimitiveType, primitiveType)
}

func ctxGetMCPPrimitiveType(r *http.Request) string {
	return ctx.GetMCPPrimitiveType(r)
}

func ctxSetMCPPrimitiveName(r *http.Request, name string) {
	setCtxValue(r, ctx.MCPPrimitiveName, name)
}

func ctxGetMCPPrimitiveName(r *http.Request) string {
	return ctx.GetMCPPrimitiveName(r)
}

func ctxSetJSONRPCErrorCode(r *http.Request, code int64) {
	setCtxValue(r, ctx.JSONRPCErrorCode, code)
}

func ctxGetJSONRPCErrorCode(r *http.Request) int64 {
	return ctx.GetJSONRPCErrorCode(r)
}

var createOauthClientSecret = func() string {
	secret := uuid.New()
	return base64.StdEncoding.EncodeToString([]byte(secret))
}

// invalidate tokens if we had a new policy

func extractOASObjFromReq(reqBody io.Reader) ([]byte, *oas.OAS, error) {
	var oasObj oas.OAS
	reqBodyInBytes, err := ioutil.ReadAll(reqBody)
	if err != nil {
		return nil, nil, ErrRequestMalformed
	}

	loader := openapi3.NewLoader()
	t, err := loader.LoadFromData(reqBodyInBytes)
	if err != nil {
		return nil, nil, ErrRequestMalformed
	}

	oasObj.T = *t

	visitor := schema.NewVisitor()
	visitor.AddSchemaManipulation(schema.TransformUnicodeEscapesToRE2Manipulation)
	visitor.ProcessOAS(&oasObj)

	reqBodyInBytes, err = json.Marshal(&oasObj)
	if err != nil {
		return nil, nil, ErrRequestMalformed
	}

	return reqBodyInBytes, &oasObj, nil
}

func validateAPIDef(apiDef *apidef.APIDefinition) *apiStatusMessage {
	validationResult := apidef.Validate(apiDef, apidef.DefaultValidationRuleSet)
	if !validationResult.IsValid {
		reason := "unknown"
		if validationResult.ErrorCount() > 0 {
			reason = validationResult.FirstError().Error()
		}

		apiErr := apiError(fmt.Sprintf("Validation of API Definition failed. Reason: %s.", reason))
		return &apiErr
	}

	return nil
}
