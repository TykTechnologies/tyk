package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// apiModifyKeySuccess represents when a Key modification was successful
type apiModifyKeySuccess struct {
	Key     string `json:"key"`
	Status  string `json:"status"`
	Action  string `json:"action"`
	KeyHash string `json:"key_hash,omitempty"`
}

// apiStatusMessage represents an API status message
type apiStatusMessage struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func apiOk(msg string) apiStatusMessage {
	return apiStatusMessage{"ok", msg}
}

func apiError(msg string) apiStatusMessage {
	return apiStatusMessage{"error", msg}
}

func doJSONWrite(w http.ResponseWriter, code int, obj interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(obj); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if code != 200 {
		job := instrument.NewJob("SystemAPIError")
		job.Event(strconv.Itoa(code))
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
		doJSONWrite(w, 405, apiError("Method not supported"))
	}
}

func getSpecForOrg(apiID string) *APISpec {
	apisMu.RLock()
	defer apisMu.RUnlock()
	for _, v := range apisByID {
		if v.OrgID == apiID {
			return v
		}
	}

	// If we can't find a spec, it doesn;t matter, because we default to Redis anyway, grab whatever you can find
	for _, v := range apisByID {
		return v
	}
	return nil
}

func checkAndApplyTrialPeriod(keyName, apiId string, newSession *user.SessionState) {
	// Check the policies to see if we are forcing an expiry on the key
	for _, polID := range newSession.PolicyIDs() {
		policiesMu.RLock()
		policy, ok := policiesByID[polID]
		policiesMu.RUnlock()
		if !ok {
			continue
		}
		// Are we foring an expiry?
		if policy.KeyExpiresIn > 0 {
			// We are, does the key exist?
			_, found := getKeyDetail(keyName, apiId, false)
			if !found {
				// this is a new key, lets expire it
				newSession.Expires = time.Now().Unix() + policy.KeyExpiresIn
			}
		}
	}
}

func applyPoliciesAndSave(keyName string, session *user.SessionState, spec *APISpec) error {
	// use basic middleware to apply policies to key/session (it also saves it)
	mw := BaseMiddleware{
		Spec: spec,
	}
	return mw.ApplyPolicies(keyName, session)
}

func doAddOrUpdate(keyName string, newSession *user.SessionState, dontReset bool) error {
	newSession.LastUpdated = strconv.Itoa(int(time.Now().Unix()))

	if len(newSession.AccessRights) > 0 {
		// We have a specific list of access rules, only add / update those
		for apiId := range newSession.AccessRights {
			apiSpec := getApiSpec(apiId)
			if apiSpec == nil {
				log.WithFields(logrus.Fields{
					"prefix":      "api",
					"key":         keyName,
					"org_id":      newSession.OrgID,
					"api_id":      apiId,
					"user_id":     "system",
					"user_ip":     "--",
					"path":        "--",
					"server_name": "system",
				}).Error("Could not add key for this API ID, API doesn't exist.")
				return errors.New("API must be active to add keys")
			}
			checkAndApplyTrialPeriod(keyName, apiId, newSession)

			// Lets reset keys if they are edited by admin
			if !apiSpec.DontSetQuotasOnCreate {
				// Reset quote by default
				if !dontReset {
					apiSpec.SessionManager.ResetQuota(keyName, newSession)
					newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
				}

				// apply polices (if any) and save key
				if err := applyPoliciesAndSave(keyName, newSession, apiSpec); err != nil {
					return err
				}
			}
		}
	} else {
		// nothing defined, add key to ALL
		if !config.Global.AllowMasterKeys {
			log.Error("Master keys disallowed in configuration, key not added.")
			return errors.New("Master keys not allowed")
		}
		log.Warning("No API Access Rights set, adding key to ALL.")
		apisMu.RLock()
		defer apisMu.RUnlock()
		for _, spec := range apisByID {
			if !dontReset {
				spec.SessionManager.ResetQuota(keyName, newSession)
				newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
			}
			checkAndApplyTrialPeriod(keyName, spec.APIID, newSession)

			// apply polices (if any) and save key
			if err := applyPoliciesAndSave(keyName, newSession, spec); err != nil {
				return err
			}
		}
	}

	log.WithFields(logrus.Fields{
		"prefix":      "api",
		"key":         obfuscateKey(keyName),
		"expires":     newSession.Expires,
		"org_id":      newSession.OrgID,
		"api_id":      "--",
		"user_id":     "system",
		"user_ip":     "--",
		"path":        "--",
		"server_name": "system",
	}).Info("Key added or updated.")
	return nil
}

func obfuscateKey(keyName string) string {
	if len(keyName) > 4 {
		return "****" + keyName[len(keyName)-4:]
	}
	return "--"
}

// ---- TODO: This changes the URL structure of the API completely ----
// ISSUE: If Session stores are stored with API specs, then managing keys will need to be done per store, i.e. add to all stores,
// remove from all stores, update to all stores, stores handle quotas separately though because they are localised! Keys will
// need to be managed by API, but only for GetDetail, GetList, UpdateKey and DeleteKey

func setSessionPassword(session *user.SessionState) {
	session.BasicAuthData.Hash = user.HashBCrypt
	newPass, err := bcrypt.GenerateFromPassword([]byte(session.BasicAuthData.Password), 10)
	if err != nil {
		log.Error("Could not hash password, setting to plaintext, error was: ", err)
		session.BasicAuthData.Hash = user.HashPlainText
		return
	}

	session.BasicAuthData.Password = string(newPass)
}

func getKeyDetail(key, apiID string, hashed bool) (user.SessionState, bool) {
	sessionManager := FallbackKeySesionManager
	if spec := getApiSpec(apiID); spec != nil {
		sessionManager = spec.SessionManager
	}

	return sessionManager.SessionDetail(key, hashed)
}

func handleAddOrUpdate(keyName string, r *http.Request) (interface{}, int) {
	var newSession user.SessionState
	if err := json.NewDecoder(r.Body).Decode(&newSession); err != nil {
		log.Error("Couldn't decode new session object: ", err)
		return apiError("Request malformed"), 400
	}
	// DO ADD OR UPDATE
	// Update our session object (create it)
	if newSession.BasicAuthData.Password != "" {
		// If we are using a basic auth user, then we need to make the keyname explicit against the OrgId in order to differentiate it
		// Only if it's NEW
		switch r.Method {
		case "POST":
			keyName = newSession.OrgID + keyName
			// It's a create, so lets hash the password
			setSessionPassword(&newSession)
		case "PUT":
			// Ge the session
			var originalKey user.SessionState
			var found bool
			for apiID := range newSession.AccessRights {
				originalKey, found = getKeyDetail(keyName, apiID, false)
				if found {
					break
				}
			}

			if !found {
				break
			}
			if originalKey.BasicAuthData.Password != newSession.BasicAuthData.Password {
				// passwords dont match assume it's new, lets hash it
				log.Debug("Passwords dont match, original: ", originalKey.BasicAuthData.Password)
				log.Debug("New: newSession.BasicAuthData.Password")
				log.Debug("Changing password")
				setSessionPassword(&newSession)
			}
		}
	}

	suppressReset := r.URL.Query().Get("suppress_reset") == "1"

	if err := doAddOrUpdate(keyName, &newSession, suppressReset); err != nil {
		return apiError("Failed to create key, ensure security settings are correct."), 500
	}

	action := "modified"
	event := EventTokenUpdated
	if r.Method == "POST" {
		action = "added"
		event = EventTokenCreated
	}
	FireSystemEvent(event, EventTokenMeta{
		EventMetaDefault: EventMetaDefault{Message: "Key modified."},
		Org:              newSession.OrgID,
		Key:              keyName,
	})

	response := apiModifyKeySuccess{
		Key:    keyName,
		Status: "ok",
		Action: action,
	}

	// add key hash for newly created key
	if config.Global.HashKeys && r.Method == http.MethodPost {
		response.KeyHash = storage.HashKey(keyName)
	}

	return response, 200
}

func handleGetDetail(sessionKey, apiID string, byHash bool) (interface{}, int) {
	if byHash && !config.Global.HashKeys {
		return apiError("Key requested by hash but key hashing is not enabled"), 400
	}

	sessionManager := FallbackKeySesionManager
	if spec := getApiSpec(apiID); spec != nil {
		sessionManager = spec.SessionManager
	}

	var session user.SessionState
	var ok bool
	session, ok = sessionManager.SessionDetail(sessionKey, byHash)
	if !ok {
		return apiError("Key not found"), 404
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    obfuscateKey(sessionKey),
		"status": "ok",
	}).Info("Retrieved key detail.")

	return session, 200
}

// apiAllKeys represents a list of keys in the memory store
type apiAllKeys struct {
	APIKeys []string `json:"keys"`
}

func handleGetAllKeys(filter, apiID string) (interface{}, int) {
	sessionManager := FallbackKeySesionManager
	if spec := getApiSpec(apiID); spec != nil {
		sessionManager = spec.SessionManager
	}

	sessions := sessionManager.Sessions(filter)

	fixed_sessions := make([]string, 0)
	for _, s := range sessions {
		if !strings.HasPrefix(s, QuotaKeyPrefix) && !strings.HasPrefix(s, RateLimitKeyPrefix) {
			fixed_sessions = append(fixed_sessions, s)
		}
	}

	sessionsObj := apiAllKeys{fixed_sessions}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"status": "ok",
	}).Info("Retrieved key list.")

	return sessionsObj, 200
}

func handleDeleteKey(keyName, apiID string) (interface{}, int) {
	if apiID == "-1" {
		// Go through ALL managed API's and delete the key
		apisMu.RLock()
		for _, spec := range apisByID {
			spec.SessionManager.RemoveSession(keyName, false)
			spec.SessionManager.ResetQuota(keyName, &user.SessionState{})
		}
		apisMu.RUnlock()

		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    keyName,
			"status": "ok",
		}).Info("Deleted key across all APIs.")

		return nil, 200
	}

	orgID := ""
	sessionManager := FallbackKeySesionManager
	if spec := getApiSpec(apiID); spec != nil {
		orgID = spec.OrgID
		sessionManager = spec.SessionManager
	}

	sessionManager.RemoveSession(keyName, false)
	sessionManager.ResetQuota(keyName, &user.SessionState{})

	statusObj := apiModifyKeySuccess{
		Key:    keyName,
		Status: "ok",
		Action: "deleted",
	}

	FireSystemEvent(EventTokenDeleted, EventTokenMeta{
		EventMetaDefault: EventMetaDefault{Message: "Key deleted."},
		Org:              orgID,
		Key:              keyName,
	})

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    keyName,
		"status": "ok",
	}).Info("Deleted key.")

	return statusObj, 200
}

func handleDeleteHashedKey(keyName, apiID string) (interface{}, int) {
	if apiID == "-1" {
		// Go through ALL managed API's and delete the key
		apisMu.RLock()
		for _, spec := range apisByID {
			spec.SessionManager.RemoveSession(keyName, true)
		}
		apisMu.RUnlock()

		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    keyName,
			"status": "ok",
		}).Info("Deleted hashed key across all APIs.")

		return nil, 200
	}

	sessionManager := FallbackKeySesionManager
	if spec := getApiSpec(apiID); spec != nil {
		sessionManager = spec.SessionManager
	}
	sessionManager.RemoveSession(keyName, true)

	statusObj := apiModifyKeySuccess{
		Key:    keyName,
		Status: "ok",
		Action: "deleted",
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    keyName,
		"status": "ok",
	}).Info("Deleted hashed key.")

	return statusObj, 200
}

func handleGetAPIList() (interface{}, int) {
	apisMu.RLock()
	defer apisMu.RUnlock()
	apiIDList := make([]*apidef.APIDefinition, len(apisByID))
	c := 0
	for _, apiSpec := range apisByID {
		apiIDList[c] = apiSpec.APIDefinition
		c++
	}
	return apiIDList, 200
}

func handleGetAPI(apiID string) (interface{}, int) {
	if spec := getApiSpec(apiID); spec != nil {
		return spec.APIDefinition, 200
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
	}).Error("API doesn't exist.")
	return apiError("API not found"), 404
}

func handleAddOrUpdateApi(apiID string, r *http.Request) (interface{}, int) {
	if config.Global.UseDBAppConfigs {
		log.Error("Rejected new API Definition due to UseDBAppConfigs = true")
		return apiError("Due to enabled use_db_app_configs, please use the Dashboard API"), 500
	}

	newDef := &apidef.APIDefinition{}
	if err := json.NewDecoder(r.Body).Decode(newDef); err != nil {
		log.Error("Couldn't decode new API Definition object: ", err)
		return apiError("Request malformed"), 400
	}

	if apiID != "" && newDef.APIID != apiID {
		log.Error("PUT operation on different APIIDs")
		return apiError("Request APIID does not match that in Definition! For Updtae operations these must match."), 400
	}

	// Create a filename
	defFilePath := filepath.Join(config.Global.AppPath, newDef.APIID+".json")

	// If it exists, delete it
	if _, err := os.Stat(defFilePath); err == nil {
		log.Warning("API Definition with this ID already exists, deleting file...")
		os.Remove(defFilePath)
	}

	// unmarshal the object into the file
	asByte, err := json.MarshalIndent(newDef, "", "  ")
	if err != nil {
		log.Error("Marshalling of API Definition failed: ", err)
		return apiError("Marshalling failed"), 500
	}

	if err := ioutil.WriteFile(defFilePath, asByte, 0644); err != nil {
		log.Error("Failed to create file! - ", err)
		return apiError("File object creation failed, write error"), 500
	}

	action := "modified"
	if r.Method == "POST" {
		action = "added"
	}

	response := apiModifyKeySuccess{
		Key:    newDef.APIID,
		Status: "ok",
		Action: action,
	}

	return response, 200
}

func handleDeleteAPI(apiID string) (interface{}, int) {
	// Generate a filename
	defFilePath := filepath.Join(config.Global.AppPath, apiID+".json")

	// If it exists, delete it
	if _, err := os.Stat(defFilePath); err != nil {
		log.Warning("File does not exist! ", err)
		return apiError("Delete failed"), 500
	}

	os.Remove(defFilePath)

	response := apiModifyKeySuccess{
		Key:    apiID,
		Status: "ok",
		Action: "deleted",
	}

	return response, 200
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]

	var obj interface{}
	var code int

	switch r.Method {
	case "GET":
		if apiID != "" {
			log.Debug("Requesting API definition for", apiID)
			obj, code = handleGetAPI(apiID)
		} else {
			log.Debug("Requesting API list")
			obj, code = handleGetAPIList()
		}
	case "POST":
		log.Debug("Creating new definition file")
		obj, code = handleAddOrUpdateApi(apiID, r)
	case "PUT":
		if apiID != "" {
			log.Debug("Updating existing API: ", apiID)
			obj, code = handleAddOrUpdateApi(apiID, r)
		} else {
			obj, code = apiError("Must specify an apiID to update"), 400
		}
	case "DELETE":
		if apiID != "" {
			log.Debug("Deleting API definition for: ", apiID)
			obj, code = handleDeleteAPI(apiID)
		} else {
			obj, code = apiError("Must specify an apiID to delete"), 400
		}
	}

	doJSONWrite(w, code, obj)
}

func keyHandler(w http.ResponseWriter, r *http.Request) {
	keyName := mux.Vars(r)["keyName"]
	apiID := r.URL.Query().Get("api_id")
	isHashed := r.URL.Query().Get("hashed") != ""

	var obj interface{}
	var code int

	switch r.Method {
	case "POST", "PUT":
		obj, code = handleAddOrUpdate(keyName, r)

	case "GET":
		if keyName != "" {
			// Return single key detail
			obj, code = handleGetDetail(keyName, apiID, isHashed)
		} else {
			// Return list of keys
			if config.Global.HashKeys {
				// get all keys is disabled by default
				if !config.Global.EnableHashedKeysListing {
					doJSONWrite(
						w,
						http.StatusNotFound,
						apiError("Hashed key listing is disabled in config (enable_hashed_keys_listing)"),
					)
					return
				}

				// we don't use filter for hashed keys
				obj, code = handleGetAllKeys("", apiID)
			} else {
				filter := r.URL.Query().Get("filter")
				obj, code = handleGetAllKeys(filter, apiID)
			}
		}

	case "DELETE":
		// Remove a key
		if !isHashed {
			obj, code = handleDeleteKey(keyName, apiID)
		} else {
			obj, code = handleDeleteHashedKey(keyName, apiID)
		}
	}

	doJSONWrite(w, code, obj)
}

type PolicyUpdateObj struct {
	Policy string `json:"policy"`
}

func policyUpdateHandler(w http.ResponseWriter, r *http.Request) {
	log.Warning("Hashed key change request detected!")

	var policRecord PolicyUpdateObj
	if err := json.NewDecoder(r.Body).Decode(&policRecord); err != nil {
		doJSONWrite(w, 400, apiError("Couldn't decode instruction"))
		return
	}

	keyName := mux.Vars(r)["keyName"]
	apiID := r.URL.Query().Get("api_id")
	obj, code := handleUpdateHashedKey(keyName, apiID, policRecord.Policy)

	doJSONWrite(w, code, obj)
}

func handleUpdateHashedKey(keyName, apiID, policyId string) (interface{}, int) {
	sessionManager := FallbackKeySesionManager
	if spec := getApiSpec(apiID); spec != nil {
		sessionManager = spec.SessionManager
	}

	sess, ok := sessionManager.SessionDetail(keyName, true)
	if !ok {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    keyName,
			"status": "fail",
		}).Error("Failed to update hashed key.")

		return apiError("Key not found"), 404
	}

	// Set the policy
	sess.LastUpdated = strconv.Itoa(int(time.Now().Unix()))
	sess.SetPolicies(policyId)

	err := sessionManager.UpdateSession(keyName, &sess, 0, true)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    keyName,
			"status": "fail",
			"err":    err,
		}).Error("Failed to update hashed key.")

		return apiError("Could not write key data"), 500
	}

	statusObj := apiModifyKeySuccess{
		Key:    keyName,
		Status: "ok",
		Action: "updated",
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    keyName,
		"status": "ok",
	}).Info("Updated hashed key.")

	return statusObj, 200
}

func orgHandler(w http.ResponseWriter, r *http.Request) {
	keyName := mux.Vars(r)["keyName"]
	filter := r.URL.Query().Get("filter")
	var obj interface{}
	var code int

	switch r.Method {
	case "POST", "PUT":
		obj, code = handleOrgAddOrUpdate(keyName, r)

	case "GET":
		if keyName != "" {
			// Return single org detail
			obj, code = handleGetOrgDetail(keyName)
		} else {
			// Return list of keys
			obj, code = handleGetAllOrgKeys(filter)
		}

	case "DELETE":
		// Remove a key
		obj, code = handleDeleteOrgKey(keyName)
	}

	doJSONWrite(w, code, obj)
}

func handleOrgAddOrUpdate(keyName string, r *http.Request) (interface{}, int) {
	newSession := new(user.SessionState)

	if err := json.NewDecoder(r.Body).Decode(newSession); err != nil {
		log.Error("Couldn't decode new session object: ", err)
		return apiError("Request malformed"), 400
	}
	// Update our session object (create it)

	spec := getSpecForOrg(keyName)
	var sessionManager SessionHandler

	if spec == nil {
		log.Warning("Couldn't find org session store in active API list")
		if config.Global.SupressDefaultOrgStore {
			return apiError("No such organisation found in Active API list"), 404
		}
		sessionManager = &DefaultOrgStore
	} else {
		sessionManager = spec.OrgSessionManager
	}

	if r.URL.Query().Get("reset_quota") == "1" {
		sessionManager.ResetQuota(keyName, newSession)
		newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
		rawKey := QuotaKeyPrefix + storage.HashKey(keyName)

		// manage quotas separately
		DefaultQuotaStore.RemoveSession(rawKey, false)
	}

	err := sessionManager.UpdateSession(keyName, newSession, 0, false)
	if err != nil {
		return apiError("Error writing to key store " + err.Error()), 500
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"org":    keyName,
		"status": "ok",
	}).Info("New organization key added or updated.")

	action := "modified"
	if r.Method == "POST" {
		action = "added"
	}

	response := apiModifyKeySuccess{
		Key:    keyName,
		Status: "ok",
		Action: action,
	}

	return response, 200
}

func handleGetOrgDetail(orgID string) (interface{}, int) {
	spec := getSpecForOrg(orgID)
	if spec == nil {
		return apiError("Org not found"), 404
	}

	session, ok := spec.OrgSessionManager.SessionDetail(orgID, false)
	if !ok {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"org":    orgID,
			"status": "fail",
			"err":    "not found",
		}).Error("Failed retrieval of record for ORG ID.")
		return apiError("Org not found"), 404
	}
	log.WithFields(logrus.Fields{
		"prefix": "api",
		"org":    orgID,
		"status": "ok",
	}).Info("Retrieved record for ORG ID.")
	return session, 200
}

func handleGetAllOrgKeys(filter string) (interface{}, int) {
	spec := getSpecForOrg("")
	if spec == nil {
		return apiError("ORG not found"), 404
	}

	sessions := spec.OrgSessionManager.Sessions(filter)
	fixed_sessions := make([]string, 0)
	for _, s := range sessions {
		if !strings.HasPrefix(s, QuotaKeyPrefix) && !strings.HasPrefix(s, RateLimitKeyPrefix) {
			fixed_sessions = append(fixed_sessions, s)
		}
	}
	sessionsObj := apiAllKeys{fixed_sessions}
	return sessionsObj, 200
}

func handleDeleteOrgKey(orgID string) (interface{}, int) {
	spec := getSpecForOrg(orgID)
	if spec == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    orgID,
			"status": "fail",
			"err":    "not found",
		}).Error("Failed to delete org key.")

		return apiError("Org not found"), 404
	}

	spec.OrgSessionManager.RemoveSession(orgID, false)
	log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    orgID,
		"status": "ok",
	}).Info("Org key deleted.")

	statusObj := apiModifyKeySuccess{
		Key:    orgID,
		Status: "ok",
		Action: "deleted",
	}
	return statusObj, 200
}

func groupResetHandler(w http.ResponseWriter, r *http.Request) {
	log.WithFields(logrus.Fields{
		"prefix": "api",
		"status": "ok",
	}).Info("Group reload accepted.")

	// Signal to the group via redis
	MainNotifier.Notify(Notification{Command: NoticeGroupReload})

	log.WithFields(logrus.Fields{
		"prefix": "api",
	}).Info("Reloaded URL Structure - Success")

	doJSONWrite(w, 200, apiOk(""))
}

// resetHandler will try to queue a reload. If fn is nil and block=true
// was in the URL parameters, it will block until the reload is done.
// Otherwise, it won't block and fn will be called once the reload is
// finished.
func resetHandler(fn func()) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var wg sync.WaitGroup

		if fn == nil && r.URL.Query().Get("block") == "true" {
			wg.Add(1)
			reloadURLStructure(wg.Done)
		} else {
			reloadURLStructure(fn)
		}

		log.WithFields(logrus.Fields{
			"prefix": "api",
		}).Info("Reload URL Structure - Scheduled")

		wg.Wait()
		doJSONWrite(w, 200, apiOk(""))
	}
}

func createKeyHandler(w http.ResponseWriter, r *http.Request) {
	newSession := new(user.SessionState)
	if err := json.NewDecoder(r.Body).Decode(newSession); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"status": "fail",
			"err":    err,
		}).Error("Key creation failed.")
		doJSONWrite(w, 500, apiError("Unmarshalling failed"))
		return
	}

	newKey := keyGen.GenerateAuthKey(newSession.OrgID)
	if newSession.HMACEnabled {
		newSession.HmacSecret = keyGen.GenerateHMACSecret()
	}

	if newSession.Certificate != "" {
		newKey = newSession.OrgID + newSession.Certificate
	}

	newSession.LastUpdated = strconv.Itoa(int(time.Now().Unix()))

	if len(newSession.AccessRights) > 0 {
		for apiID := range newSession.AccessRights {
			apiSpec := getApiSpec(apiID)
			if apiSpec != nil {
				checkAndApplyTrialPeriod(newKey, apiID, newSession)
				// If we have enabled HMAC checking for keys, we need to generate a secret for the client to use
				if !apiSpec.DontSetQuotasOnCreate {
					// Reset quota by default
					apiSpec.SessionManager.ResetQuota(newKey, newSession)
					newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
				}
				// apply polices (if any) and save key
				if err := applyPoliciesAndSave(newKey, newSession, apiSpec); err != nil {
					doJSONWrite(w, 500, apiError("Failed to create key - "+err.Error()))
					return
				}
			} else {
				// Use fallback
				sessionManager := FallbackKeySesionManager
				newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
				sessionManager.ResetQuota(newKey, newSession)
				err := sessionManager.UpdateSession(newKey, newSession, -1, false)
				if err != nil {
					doJSONWrite(w, 500, apiError("Failed to create key - "+err.Error()))
					return
				}
			}
		}
	} else {
		if config.Global.AllowMasterKeys {
			// nothing defined, add key to ALL
			log.WithFields(logrus.Fields{
				"prefix":      "api",
				"status":      "warning",
				"org_id":      newSession.OrgID,
				"api_id":      "--",
				"user_id":     "system",
				"user_ip":     requestIPHops(r),
				"path":        "--",
				"server_name": "system",
			}).Warning("No API Access Rights set on key session, adding key to all APIs.")

			apisMu.RLock()
			defer apisMu.RUnlock()
			for _, spec := range apisByID {
				checkAndApplyTrialPeriod(newKey, spec.APIID, newSession)
				if !spec.DontSetQuotasOnCreate {
					// Reset quote by default
					spec.SessionManager.ResetQuota(newKey, newSession)
					newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
				}
				// apply polices (if any) and save key
				if err := applyPoliciesAndSave(newKey, newSession, spec); err != nil {
					doJSONWrite(w, 500, apiError("Failed to create key - "+err.Error()))
					return
				}
			}
		} else {
			log.WithFields(logrus.Fields{
				"prefix":      "api",
				"status":      "error",
				"err":         "master keys disabled",
				"org_id":      newSession.OrgID,
				"api_id":      "--",
				"user_id":     "system",
				"user_ip":     requestIPHops(r),
				"path":        "--",
				"server_name": "system",
			}).Error("Master keys disallowed in configuration, key not added.")

			doJSONWrite(w, 400, apiError("Failed to create key, keys must have at least one Access Rights record set."))
			return
		}

	}

	obj := apiModifyKeySuccess{
		Action: "added",
		Key:    newKey,
		Status: "ok",
	}

	// add key hash to reply
	if config.Global.HashKeys {
		obj.KeyHash = storage.HashKey(newKey)
	}

	FireSystemEvent(EventTokenCreated, EventTokenMeta{
		EventMetaDefault: EventMetaDefault{Message: "Key generated."},
		Org:              newSession.OrgID,
		Key:              newKey,
	})

	log.WithFields(logrus.Fields{
		"prefix":      "api",
		"key":         obfuscateKey(newKey),
		"status":      "ok",
		"api_id":      "--",
		"org_id":      newSession.OrgID,
		"user_id":     "system",
		"user_ip":     requestIPHops(r),
		"path":        "--",
		"server_name": "system",
	}).Info("Generated new key: (", obfuscateKey(newKey), ")")

	doJSONWrite(w, 200, obj)
}

// NewClientRequest is an outward facing JSON object translated from osin OAuthClients
type NewClientRequest struct {
	ClientID          string `json:"client_id"`
	ClientRedirectURI string `json:"redirect_uri"`
	APIID             string `json:"api_id"`
	PolicyID          string `json:"policy_id"`
	ClientSecret      string `json:"secret"`
}

func oauthClientStorageID(clientID string) string {
	return prefixClient + clientID
}

func createOauthClient(w http.ResponseWriter, r *http.Request) {
	var newOauthClient NewClientRequest
	if err := json.NewDecoder(r.Body).Decode(&newOauthClient); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"status": "fail",
			"err":    err,
		}).Error("Failed to create OAuth client")
		doJSONWrite(w, 500, apiError("Unmarshalling failed"))
		return
	}

	// Allow the client ID to be set
	cleanSting := newOauthClient.ClientID

	if newOauthClient.ClientID == "" {
		u5 := uuid.NewV4()
		cleanSting = strings.Replace(u5.String(), "-", "", -1)
	}

	// Allow the secret to be set
	secret := newOauthClient.ClientSecret
	if newOauthClient.ClientSecret == "" {
		u5Secret := uuid.NewV4()
		secret = base64.StdEncoding.EncodeToString([]byte(u5Secret.String()))
	}

	newClient := OAuthClient{
		ClientID:          cleanSting,
		ClientRedirectURI: newOauthClient.ClientRedirectURI,
		ClientSecret:      secret,
		PolicyID:          newOauthClient.PolicyID,
	}

	storageID := oauthClientStorageID(newClient.GetId())
	log.WithFields(logrus.Fields{
		"prefix": "api",
	}).Debug("Created storage ID: ", storageID)

	if newOauthClient.APIID != "" {
		// set client only for passed API ID
		apiSpec := getApiSpec(newOauthClient.APIID)
		if apiSpec == nil {
			log.WithFields(logrus.Fields{
				"prefix": "api",
				"apiID":  newOauthClient.APIID,
				"status": "fail",
				"err":    "API doesn't exist",
			}).Error("Failed to create OAuth client")
			doJSONWrite(w, 500, apiError("API doesn't exist"))
			return
		}

		err := apiSpec.OAuthManager.OsinServer.Storage.SetClient(storageID, &newClient, true)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "api",
				"apiID":  newOauthClient.APIID,
				"status": "fail",
				"err":    err,
			}).Error("Failed to create OAuth client")
			doJSONWrite(w, 500, apiError("Failure in storing client data."))
			return
		}
	} else {
		// set client for all APIs from the given policy
		policiesMu.RLock()
		policy, ok := policiesByID[newClient.PolicyID]
		policiesMu.RUnlock()
		if !ok {
			log.WithFields(logrus.Fields{
				"prefix":   "api",
				"policyID": newClient.PolicyID,
				"status":   "fail",
				"err":      "Policy doesn't exist",
			}).Error("Failed to create OAuth client")
			doJSONWrite(w, 500, apiError("Policy doesn't exist"))
			return
		}
		// iterate over APIs and set client for each of them
		for apiID := range policy.AccessRights {
			apiSpec := getApiSpec(apiID)
			if apiSpec == nil {
				log.WithFields(logrus.Fields{
					"prefix": "api",
					"apiID":  apiID,
					"status": "fail",
					"err":    "API doesn't exist",
				}).Error("Failed to create OAuth client")
				doJSONWrite(w, 500, apiError("API doesn't exist"))
				return
			}
			// set oauth client if it is oauth API
			if apiSpec.UseOauth2 {
				err := apiSpec.OAuthManager.OsinServer.Storage.SetClient(storageID, &newClient, true)
				if err != nil {
					log.WithFields(logrus.Fields{
						"prefix": "api",
						"apiID":  apiID,
						"status": "fail",
						"err":    err,
					}).Error("Failed to create OAuth client")
					doJSONWrite(w, 500, apiError("Failure in storing client data."))
					return
				}
			}
		}
	}

	clientData := NewClientRequest{
		ClientID:          newClient.GetId(),
		ClientSecret:      newClient.GetSecret(),
		ClientRedirectURI: newClient.GetRedirectUri(),
		PolicyID:          newClient.GetPolicyID(),
	}

	log.WithFields(logrus.Fields{
		"prefix":            "api",
		"apiID":             newOauthClient.APIID,
		"clientID":          clientData.ClientID,
		"clientRedirectURI": clientData.ClientRedirectURI,
		"policyID":          clientData.PolicyID,
		"status":            "ok",
	}).Info("Created OAuth client")

	doJSONWrite(w, 200, clientData)
}

func invalidateOauthRefresh(w http.ResponseWriter, r *http.Request) {
	apiID := r.URL.Query().Get("api_id")
	if apiID == "" {
		doJSONWrite(w, 400, apiError("Missing parameter api_id"))
		return
	}
	apiSpec := getApiSpec(apiID)

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
	}).Debug("Looking for refresh token in API Register")

	if apiSpec == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    "API not found",
		}).Error("Failed to invalidate refresh token")

		doJSONWrite(w, 404, apiError("API for this refresh token not found"))
		return
	}

	if apiSpec.OAuthManager == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    "API is not OAuth",
		}).Error("Failed to invalidate refresh token")

		doJSONWrite(w, 400, apiError("OAuth is not enabled on this API"))
		return
	}

	keyName := mux.Vars(r)["keyName"]
	err := apiSpec.OAuthManager.OsinServer.Storage.RemoveRefresh(keyName)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    err,
		}).Error("Failed to invalidate refresh token")

		doJSONWrite(w, 500, apiError("Failed to invalidate refresh token"))
		return
	}

	success := apiModifyKeySuccess{
		Key:    keyName,
		Status: "ok",
		Action: "deleted",
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
		"token":  keyName,
		"status": "ok",
	}).Info("Invalidated refresh token")

	doJSONWrite(w, 200, success)
}

func oAuthClientHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	keyName := mux.Vars(r)["keyName"]

	var obj interface{}
	var code int
	switch r.Method {
	case "GET":
		if keyName != "" {
			// Return single client detail
			obj, code = getOauthClientDetails(keyName, apiID)
		} else {
			// Return list of keys
			obj, code = getOauthClients(apiID)
		}
	case "DELETE":
		// Remove a key
		obj, code = handleDeleteOAuthClient(keyName, apiID)
	}

	doJSONWrite(w, code, obj)
}

func oAuthClientTokensHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	keyName := mux.Vars(r)["keyName"]

	apiSpec := getApiSpec(apiID)
	if apiSpec == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"client": keyName,
			"err":    "not found",
		}).Error("Failed to retrieve OAuth tokens")
		doJSONWrite(w, http.StatusNotFound, apiError("OAuth Client ID not found"))
		return
	}

	// get tokens from redis
	// TODO: add pagination
	tokens, err := apiSpec.OAuthManager.OsinServer.Storage.GetClientTokens(keyName)
	if err != nil {
		doJSONWrite(w, http.StatusInternalServerError, apiError("Get client tokens failed"))
		return
	}

	doJSONWrite(w, http.StatusOK, tokens)
}

// Get client details
func getOauthClientDetails(keyName, apiID string) (interface{}, int) {
	storageID := oauthClientStorageID(keyName)
	apiSpec := getApiSpec(apiID)
	if apiSpec == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"client": keyName,
			"err":    "not found",
		}).Error("Failed to retrieve OAuth client details")
		return apiError("OAuth Client ID not found"), 404
	}

	clientData, err := apiSpec.OAuthManager.OsinServer.Storage.GetClientNoPrefix(storageID)
	if err != nil {
		return apiError("OAuth Client ID not found"), 404
	}
	reportableClientData := NewClientRequest{
		ClientID:          clientData.GetId(),
		ClientSecret:      clientData.GetSecret(),
		ClientRedirectURI: clientData.GetRedirectUri(),
		PolicyID:          clientData.GetPolicyID(),
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
		"status": "ok",
		"client": keyName,
	}).Info("Retrieved OAuth client ID")

	return reportableClientData, 200
}

// Delete Client
func handleDeleteOAuthClient(keyName, apiID string) (interface{}, int) {
	storageID := oauthClientStorageID(keyName)

	apiSpec := getApiSpec(apiID)
	if apiSpec == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"client": keyName,
			"err":    "not found",
		}).Error("Failed to delete OAuth client")

		return apiError("OAuth Client ID not found"), 404
	}

	err := apiSpec.OAuthManager.OsinServer.Storage.DeleteClient(storageID, true)
	if err != nil {
		return apiError("Delete failed"), 500
	}

	statusObj := apiModifyKeySuccess{
		Key:    keyName,
		Status: "ok",
		Action: "deleted",
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
		"status": "ok",
		"client": keyName,
	}).Info("Deleted OAuth client")

	return statusObj, 200
}

const oAuthNotPropagatedErr = "OAuth client list isn't available or hasn't been propagated yet."

// List Clients
func getOauthClients(apiID string) (interface{}, int) {
	filterID := prefixClient

	apiSpec := getApiSpec(apiID)
	if apiSpec == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    "API not found",
		}).Error("Failed to retrieve OAuth client list.")

		return apiError("OAuth Client ID not found"), 404
	}

	if apiSpec.OAuthManager == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    "API not found",
		}).Error("Failed to retrieve OAuth client list.")

		return apiError(oAuthNotPropagatedErr), 400
	}

	clientData, err := apiSpec.OAuthManager.OsinServer.Storage.GetClients(filterID, true)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    err,
		}).Error("Failed to report OAuth client list")

		return apiError("OAuth slients not found"), 404
	}
	clients := []NewClientRequest{}
	for _, osinClient := range clientData {
		reportableClientData := NewClientRequest{
			ClientID:          osinClient.GetId(),
			ClientSecret:      osinClient.GetSecret(),
			ClientRedirectURI: osinClient.GetRedirectUri(),
			PolicyID:          osinClient.GetPolicyID(),
		}

		clients = append(clients, reportableClientData)
	}
	log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
		"status": "ok",
	}).Info("Retrieved OAuth client list")

	return clients, 200
}

func healthCheckhandler(w http.ResponseWriter, r *http.Request) {
	if !config.Global.HealthCheck.EnableHealthChecks {
		doJSONWrite(w, 400, apiError("Health checks are not enabled for this node"))
		return
	}
	apiID := r.URL.Query().Get("api_id")
	if apiID == "" {
		doJSONWrite(w, 400, apiError("missing api_id parameter"))
		return
	}
	apiSpec := getApiSpec(apiID)
	if apiSpec == nil {
		doJSONWrite(w, 404, apiError("API ID not found"))
		return
	}
	health, _ := apiSpec.Health.ApiHealthValues()
	doJSONWrite(w, 200, health)
}

func userRatesCheck(w http.ResponseWriter, r *http.Request) {
	session := ctxGetSession(r)
	if session == nil {
		doJSONWrite(w, 400, apiError("Health checks are not enabled for this node"))
		return
	}

	returnSession := PublicSession{}
	returnSession.Quota.QuotaRenews = session.QuotaRenews
	returnSession.Quota.QuotaRemaining = session.QuotaRemaining
	returnSession.Quota.QuotaMax = session.QuotaMax
	returnSession.RateLimit.Rate = session.Rate
	returnSession.RateLimit.Per = session.Per

	doJSONWrite(w, 200, returnSession)
}

func invalidateCacheHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]

	keyPrefix := "cache-" + apiID
	matchPattern := keyPrefix + "*"
	store := storage.RedisCluster{KeyPrefix: keyPrefix, IsCache: true}

	if ok := store.DeleteScanMatch(matchPattern); !ok {
		err := errors.New("scan/delete failed")
		var orgid string
		if spec := getApiSpec(apiID); spec != nil {
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

		doJSONWrite(w, 500, apiError("Cache invalidation failed"))
		return
	}

	doJSONWrite(w, 200, apiOk("cache invalidated"))
}

// TODO: Don't modify http.Request values in-place. We must right now
// because our middleware design doesn't pass around http.Request
// pointers, so we have no way to modify the pointer in a middleware.
//
// If we ever redesign middlewares - or if we find another workaround -
// revisit this.
func setContext(r *http.Request, ctx context.Context) {
	r2 := r.WithContext(ctx)
	*r = *r2
}
func setCtxValue(r *http.Request, key, val interface{}) {
	setContext(r, context.WithValue(r.Context(), key, val))
}

func ctxGetData(r *http.Request) map[string]interface{} {
	if v := r.Context().Value(ContextData); v != nil {
		return v.(map[string]interface{})
	}
	return nil
}

func ctxSetData(r *http.Request, m map[string]interface{}) {
	if m == nil {
		panic("setting a nil context ContextData")
	}
	setCtxValue(r, ContextData, m)
}

func ctxGetSession(r *http.Request) *user.SessionState {
	if v := r.Context().Value(SessionData); v != nil {
		return v.(*user.SessionState)
	}
	return nil
}

func ctxSetSession(r *http.Request, s *user.SessionState) {
	if s == nil {
		panic("setting a nil context SessionData")
	}
	setCtxValue(r, SessionData, s)
}

func ctxGetAuthToken(r *http.Request) string {
	if v := r.Context().Value(AuthHeaderValue); v != nil {
		return v.(string)
	}
	return ""
}

func ctxSetAuthToken(r *http.Request, t string) {
	if t == "" {
		panic("setting a nil context AuthHeaderValue")
	}
	setCtxValue(r, AuthHeaderValue, t)
}

func ctxGetTrackedPath(r *http.Request) string {
	if v := r.Context().Value(TrackThisEndpoint); v != nil {
		return v.(string)
	}
	return ""
}

func ctxSetTrackedPath(r *http.Request, p string) {
	if p == "" {
		panic("setting a nil context TrackThisEndpoint")
	}
	setCtxValue(r, TrackThisEndpoint, p)
}

func ctxGetDoNotTrack(r *http.Request) bool {
	return r.Context().Value(DoNotTrackThisEndpoint) == true
}

func ctxSetDoNotTrack(r *http.Request, b bool) {
	setCtxValue(r, DoNotTrackThisEndpoint, b)
}

func ctxGetVersionInfo(r *http.Request) *apidef.VersionInfo {
	if v := r.Context().Value(VersionData); v != nil {
		return v.(*apidef.VersionInfo)
	}
	return nil
}

func ctxSetVersionInfo(r *http.Request, v *apidef.VersionInfo) {
	if v == nil {
		panic("setting a nil context VersionData")
	}
	setCtxValue(r, VersionData, v)
}

func ctxSetUrlRewritePath(r *http.Request, path string) {
	setCtxValue(r, UrlRewritePath, path)
}

func ctxGetUrlRewritePath(r *http.Request) string {
	if v := r.Context().Value(UrlRewritePath); v != nil {
		if strVal, ok := v.(string); ok {
			return strVal
		}
	}
	return ""
}
func ctxGetDefaultVersion(r *http.Request) bool {
	return r.Context().Value(VersionDefault) != nil
}

func ctxSetDefaultVersion(r *http.Request) {
	setCtxValue(r, VersionDefault, true)
}
