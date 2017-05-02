package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/TykTechnologies/tyk/apidef"
)

// APIModifyKeySuccess represents when a Key modification was successful
type APIModifyKeySuccess struct {
	Key    string `json:"key"`
	Status string `json:"status"`
	Action string `json:"action"`
}

// APIErrorMessage is an object that defines when a generic error occurred
type APIErrorMessage struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

func createError(errorMsg string) []byte {
	errorObj := APIErrorMessage{"error", errorMsg}
	responseMsg, err := json.Marshal(&errorObj)

	if err != nil {
		log.Error("Couldn't marshal error stats: ", err)
	}

	return responseMsg
}

func doJSONWrite(w http.ResponseWriter, code int, responseMessage []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(responseMessage)
	if code != 200 {
		job := instrument.NewJob("SystemAPIError")
		job.Event(strconv.Itoa(code))
	}
}

func GetSpecForApi(apiID string) *APISpec {
	if ApiSpecRegister == nil {
		log.Error("No API Register present!")
		return nil
	}

	return ApiSpecRegister[apiID]
}

func GetSpecForOrg(apiID string) *APISpec {
	var aKey string
	for k, v := range ApiSpecRegister {
		if v.OrgID == apiID {
			return v
		}
		aKey = k
	}

	// If we can't find a spec, it doesn;t matter, because we default to Redis anyway, grab whatever you can find
	return ApiSpecRegister[aKey]
}

func checkAndApplyTrialPeriod(keyName, apiId string, newSession *SessionState) {
	// Check the policy to see if we are forcing an expiry on the key
	if newSession.ApplyPolicyID == "" {
		return
	}
	policy, ok := Policies[newSession.ApplyPolicyID]
	if !ok {
		return
	}
	// Are we foring an expiry?
	if policy.KeyExpiresIn > 0 {
		// We are, does the key exist?
		_, found := GetKeyDetail(keyName, apiId)
		if !found {
			// this is a new key, lets expire it
			newSession.Expires = time.Now().Unix() + policy.KeyExpiresIn
		}

	}
}

func doAddOrUpdate(keyName string, newSession SessionState, dontReset bool) error {
	newSession.LastUpdated = strconv.Itoa(int(time.Now().Unix()))

	if len(newSession.AccessRights) > 0 {
		// We have a specific list of access rules, only add / update those
		for apiId := range newSession.AccessRights {
			apiSpec := GetSpecForApi(apiId)
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
			checkAndApplyTrialPeriod(keyName, apiId, &newSession)

			// Lets reset keys if they are edited by admin
			if !apiSpec.DontSetQuotasOnCreate {
				// Reset quote by default
				if !dontReset {
					apiSpec.SessionManager.ResetQuota(keyName, newSession)
					newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
				}

				err := apiSpec.SessionManager.UpdateSession(keyName, newSession, getLifetime(apiSpec, &newSession))
				if err != nil {
					return err
				}
			}
		}
	} else {
		// nothing defined, add key to ALL
		if !config.AllowMasterKeys {
			log.Error("Master keys disallowed in configuration, key not added.")
			return errors.New("Master keys not allowed")
		}
		log.Warning("No API Access Rights set, adding key to ALL.")
		for _, spec := range ApiSpecRegister {
			if !dontReset {
				spec.SessionManager.ResetQuota(keyName, newSession)
				newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
			}
			checkAndApplyTrialPeriod(keyName, spec.APIID, &newSession)
			err := spec.SessionManager.UpdateSession(keyName, newSession, getLifetime(spec, &newSession))
			if err != nil {
				return err
			}
		}
	}

	log.WithFields(logrus.Fields{
		"prefix":      "api",
		"key":         ObfuscateKeyString(keyName),
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

func ObfuscateKeyString(keyName string) string {
	obfuscated := "--"

	if len(keyName) > 4 {
		obfuscated = "****" + keyName[len(keyName)-4:]
	}

	return obfuscated
}

// ---- TODO: This changes the URL structure of the API completely ----
// ISSUE: If Session stores are stored with API specs, then managing keys will need to be done per store, i.e. add to all stores,
// remove from all stores, update to all stores, stores handle quotas separately though because they are localised! Keys will
// need to be managed by API, but only for GetDetail, GetList, UpdateKey and DeleteKey

func SetSessionPassword(session *SessionState) {
	session.BasicAuthData.Hash = HashBCrypt
	newPass, err := bcrypt.GenerateFromPassword([]byte(session.BasicAuthData.Password), 10)
	if err != nil {
		log.Error("Could not hash password, setting to plaintext, error was: ", err)
		session.BasicAuthData.Hash = HashPlainText
		return
	}

	session.BasicAuthData.Password = string(newPass)
}

func GetKeyDetail(key, apiID string) (SessionState, bool) {

	sessionManager := FallbackKeySesionManager
	if apiID != "" {
		spec := GetSpecForApi(apiID)
		if spec != nil {
			sessionManager = spec.SessionManager
		}
	}

	return sessionManager.GetSessionDetail(key)
}

func handleAddOrUpdate(keyName string, r *http.Request) ([]byte, int) {
	var newSession SessionState
	if err := json.NewDecoder(r.Body).Decode(&newSession); err != nil {
		log.Error("Couldn't decode new session object: ", err)
		return createError("Request malformed"), 400
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
			SetSessionPassword(&newSession)
		case "PUT":
			// Ge the session
			var originalKey SessionState
			var found bool
			for api_id := range newSession.AccessRights {
				originalKey, found = GetKeyDetail(keyName, api_id)
				if found {
					break
				}
			}

			if found {
				// Found the key
				if originalKey.BasicAuthData.Password != newSession.BasicAuthData.Password {
					// passwords dont match assume it's new, lets hash it
					log.Debug("Passwords dont match, original: ", originalKey.BasicAuthData.Password)
					log.Debug("New: newSession.BasicAuthData.Password")
					log.Debug("Changing password")
					SetSessionPassword(&newSession)
				}
			}
		}

	}
	suppressReset := r.FormValue("suppress_reset") == "1"
	if err := doAddOrUpdate(keyName, newSession, suppressReset); err != nil {
		return createError("Failed to create key, ensure security settings are correct."), 500
	}

	action := "modified"
	event := EventTokenUpdated
	if r.Method == "POST" {
		action = "added"
		event = EventTokenCreated
	}

	response := APIModifyKeySuccess{
		keyName,
		"ok",
		action,
	}

	responseMessage, err := json.Marshal(&response)
	if err != nil {
		log.Error("Could not create response message: ", err)
		return systemError, 500
	}

	FireSystemEvent(event, EventTokenMeta{
		EventMetaDefault: EventMetaDefault{
			Message:            "Key modified.",
			OriginatingRequest: "",
		},
		Org: newSession.OrgID,
		Key: keyName,
	})

	return responseMessage, 200
}

func handleGetDetail(sessionKey, apiID string) ([]byte, int) {
	success := true
	var responseMessage []byte
	var err error

	sessionManager := FallbackKeySesionManager
	if apiID != "" {
		spec := GetSpecForApi(apiID)
		if spec != nil {
			sessionManager = spec.SessionManager
		}
	}

	session, ok := sessionManager.GetSessionDetail(sessionKey)
	if !ok {
		success = false
	} else {
		responseMessage, err = json.Marshal(&session)
		if err != nil {
			log.Error("Marshalling failed: ", err)
			success = false
		}
	}

	if !success {
		notFound := APIStatusMessage{"error", "Key not found"}
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    ObfuscateKeyString(sessionKey),
			"status": "fail",
			"err":    "not found",
		}).Warning("Failed to retrieve key detail.")
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 404
	}
	log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    ObfuscateKeyString(sessionKey),
		"status": "ok",
	}).Info("Retrieved key detail.")

	return responseMessage, 200
}

// APIAllKeys represents a list of keys in the memory store
type APIAllKeys struct {
	APIKeys []string `json:"keys"`
}

func handleGetAllKeys(filter, apiID string) ([]byte, int) {
	var responseMessage []byte

	var err error

	if config.HashKeys {
		errorMsg := APIErrorMessage{
			Status: "error",
			Error:  "Configuration is secured, key listings not available in hashed configurations",
		}
		errJSON, _ := json.Marshal(&errorMsg)
		return errJSON, 400
	}

	sessionManager := FallbackKeySesionManager
	if apiID != "" {
		spec := GetSpecForApi(apiID)
		if spec != nil {
			sessionManager = spec.SessionManager
		}
	}

	sessions := sessionManager.GetSessions(filter)

	fixed_sessions := make([]string, 0)
	for _, s := range sessions {
		if !strings.Contains(s, QuotaKeyPrefix) && !strings.Contains(s, RateLimitKeyPrefix) {
			fixed_sessions = append(fixed_sessions, s)
		}
	}

	sessionsObj := APIAllKeys{fixed_sessions}

	responseMessage, err = json.Marshal(&sessionsObj)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"status": "fail",
			"err":    err,
		}).Error("Failed to retrieve key list.")

		return systemError, 500
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"status": "ok",
	}).Info("Retrieved key list.")

	return responseMessage, 200
}

// APIStatusMessage represents an API status message
type APIStatusMessage struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func handleDeleteKey(keyName, apiID string) ([]byte, int) {
	var responseMessage []byte
	var err error

	if apiID == "-1" {
		// Go through ALL managed API's and delete the key
		for _, spec := range ApiSpecRegister {
			spec.SessionManager.RemoveSession(keyName)
			spec.SessionManager.ResetQuota(keyName, SessionState{})
		}

		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    keyName,
			"status": "ok",
		}).Info("Deleted key across all APIs.")

		return responseMessage, 200
	}

	orgID := ""
	sessionManager := FallbackKeySesionManager
	if apiID != "" {
		spec := GetSpecForApi(apiID)
		if spec != nil {
			orgID = spec.OrgID
			sessionManager = spec.SessionManager
		}
	}

	sessionManager.RemoveSession(keyName)
	sessionManager.ResetQuota(keyName, SessionState{})

	statusObj := APIModifyKeySuccess{keyName, "ok", "deleted"}
	responseMessage, err = json.Marshal(&statusObj)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    keyName,
			"status": "fail",
			"err":    err,
		}).Error("Failed to delete key.")
		return systemError, 500
	}

	FireSystemEvent(EventTokenDeleted, EventTokenMeta{
		EventMetaDefault: EventMetaDefault{
			Message:            "Key deleted.",
			OriginatingRequest: "",
		},
		Org: orgID,
		Key: keyName,
	})

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    keyName,
		"status": "ok",
	}).Info("Deleted key.")

	return responseMessage, 200
}

func handleDeleteHashedKey(keyName, apiID string) ([]byte, int) {
	var responseMessage []byte
	var err error

	if apiID == "-1" {
		// Go through ALL managed API's and delete the key
		for _, spec := range ApiSpecRegister {
			spec.SessionManager.RemoveSession(keyName)
		}

		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    keyName,
			"status": "ok",
		}).Info("Deleted hashed key across all APIs.")

		return responseMessage, 200
	}

	sessionManager := FallbackKeySesionManager
	if apiID != "" {
		spec := GetSpecForApi(apiID)
		if spec != nil {
			sessionManager = spec.SessionManager
		}
	}

	// This is so we bypass the hash function
	sessStore := sessionManager.GetStore()

	// TODO: This is pretty ugly
	setKeyName := "apikey-" + keyName
	sessStore.DeleteRawKey(setKeyName)

	statusObj := APIModifyKeySuccess{keyName, "ok", "deleted"}
	responseMessage, err = json.Marshal(&statusObj)

	if err != nil {
		log.Error("Marshalling failed: ", err)
		return systemError, 500
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    keyName,
		"status": "ok",
	}).Info("Deleted hashed key.")

	return responseMessage, 200
}

func handleURLReload(fn func()) ([]byte, int) {
	var responseMessage []byte
	var err error

	reloadURLStructure(fn)

	statusObj := APIErrorMessage{"ok", ""}
	responseMessage, err = json.Marshal(&statusObj)

	if err != nil {
		log.Error("Marshalling failed: ", err)
		return systemError, 500
	}

	log.WithFields(logrus.Fields{
		"prefix": "api"}).Info("Reload URL Structure - Scheduled")

	return responseMessage, 200
}

func signalGroupReload() ([]byte, int) {
	var responseMessage []byte
	var err error

	notice := Notification{
		Command: NoticeGroupReload,
	}

	// Signal to the group via redis
	MainNotifier.Notify(notice)

	statusObj := APIErrorMessage{"ok", ""}
	responseMessage, err = json.Marshal(&statusObj)

	if err != nil {
		log.Error("Marshalling failed: ", err)
		return systemError, 500
	}

	log.WithFields(logrus.Fields{
		"prefix": "api"}).Info("Reloaded URL Structure - Success")

	return responseMessage, 200
}

func handleGetAPIList() ([]byte, int) {
	var responseMessage []byte
	var err error

	apiIDList := make([]*apidef.APIDefinition, len(ApiSpecRegister))

	c := 0
	for _, apiSpec := range ApiSpecRegister {
		apiIDList[c] = apiSpec.APIDefinition
		apiIDList[c].RawData = nil
		c++
	}

	responseMessage, err = json.Marshal(&apiIDList)

	if err != nil {
		log.Error("Marshalling failed: ", err)
		return systemError, 500
	}

	return responseMessage, 200
}

func handleGetAPI(apiID string) ([]byte, int) {
	var responseMessage []byte
	var err error

	for _, apiSpec := range ApiSpecRegister {
		if apiSpec.APIDefinition.APIID == apiID {

			responseMessage, err = json.Marshal(apiSpec.APIDefinition)

			if err != nil {
				log.Error("Marshalling failed: ", err)
				return systemError, 500
			}

			return responseMessage, 200
		}
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
	}).Error("API doesn't exist.")
	notFound := APIStatusMessage{"error", "API not found"}
	responseMessage, _ = json.Marshal(&notFound)
	return responseMessage, 404
}

func handleAddOrUpdateApi(apiID string, r *http.Request) ([]byte, int) {
	if config.UseDBAppConfigs {
		log.Error("Rejected new API Definition due to UseDBAppConfigs = true")
		return createError("Due to enabled use_db_app_configs, please use the Dashboard API"), 500
	}

	newDef := &apidef.APIDefinition{}
	if err := json.NewDecoder(r.Body).Decode(newDef); err != nil {
		log.Error("Couldn't decode new API Definition object: ", err)
		return createError("Request malformed"), 400
	}

	if apiID != "" && newDef.APIID != apiID {
		log.Error("PUT operation on different APIIDs")
		return createError("Request APIID does not match that in Definition! For Updtae operations these must match."), 400
	}

	// Create a filename
	defFilePath := filepath.Join(config.AppPath, newDef.APIID+".json")

	// If it exists, delete it
	if _, err := os.Stat(defFilePath); err == nil {
		log.Warning("API Definition with this ID already exists, deleting file...")
		os.Remove(defFilePath)
	}

	// unmarshal the object into the file
	asByte, err := json.MarshalIndent(newDef, "", "  ")
	if err != nil {
		log.Error("Marshalling of API Definition failed: ", err)
		return createError("Marshalling failed"), 500
	}

	if err := ioutil.WriteFile(defFilePath, asByte, 0644); err != nil {
		log.Error("Failed to create file! - ", err)
		return createError("File object creation failed, write error"), 500
	}

	action := "modified"
	if r.Method == "POST" {
		action = "added"
	}

	response := APIModifyKeySuccess{
		newDef.APIID,
		"ok",
		action}

	responseMessage, err := json.Marshal(&response)

	if err != nil {
		log.Error("Could not create response message: ", err)
		return systemError, 500
	}

	return responseMessage, 200
}

func handleDeleteAPI(apiID string) ([]byte, int) {
	// Generate a filename
	defFilePath := filepath.Join(config.AppPath, apiID+".json")

	// If it exists, delete it
	if _, err := os.Stat(defFilePath); err != nil {
		log.Warning("File does not exist! ", err)
		return createError("Delete failed"), 500
	}

	os.Remove(defFilePath)

	response := APIModifyKeySuccess{
		apiID,
		"ok",
		"deleted"}

	responseMessage, err := json.Marshal(&response)

	if err != nil {
		log.Error("Could not create response message: ", err)
		return systemError, 500
	}

	return responseMessage, 200
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	var apiID string

	if r.URL.Path != "/tyk/apis" {
		apiID = r.URL.Path[len("/tyk/apis/"):]
	}

	var responseMessage []byte
	var code int

	switch r.Method {
	case "GET":
		if apiID != "" {
			log.Debug("Requesting API definition for", apiID)
			responseMessage, code = handleGetAPI(apiID)
		} else {
			log.Debug("Requesting API list")
			responseMessage, code = handleGetAPIList()
		}
	case "POST":
		log.Debug("Creating new definition file")
		responseMessage, code = handleAddOrUpdateApi(apiID, r)
	case "PUT":
		if apiID != "" {
			log.Debug("Updating existing API: ", apiID)
			responseMessage, code = handleAddOrUpdateApi(apiID, r)
		} else {
			code = 400
			responseMessage = createError("Must specify an apiID to update")
		}
	case "DELETE":
		if apiID != "" {
			log.Debug("Deleting API definition for: ", apiID)
			responseMessage, code = handleDeleteAPI(apiID)
		} else {
			code = 400
			responseMessage = createError("Must specify an apiID to delete")
		}
	default:
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	doJSONWrite(w, code, responseMessage)
}

func keyHandler(w http.ResponseWriter, r *http.Request) {
	keyName := r.URL.Path[len("/tyk/keys/"):]
	filter := r.FormValue("filter")
	apiID := r.FormValue("api_id")
	var responseMessage []byte
	var code int

	switch r.Method {
	case "POST", "PUT":
		responseMessage, code = handleAddOrUpdate(keyName, r)

	case "GET":
		if keyName != "" {
			// Return single key detail
			responseMessage, code = handleGetDetail(keyName, apiID)
		} else {
			// Return list of keys
			responseMessage, code = handleGetAllKeys(filter, apiID)
		}

	case "DELETE":
		hashed := r.FormValue("hashed")
		// Remove a key
		if hashed == "" {
			responseMessage, code = handleDeleteKey(keyName, apiID)
		} else {
			responseMessage, code = handleDeleteHashedKey(keyName, apiID)
		}

	default:
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	doJSONWrite(w, code, responseMessage)
}

type PolicyUpdateObj struct {
	Policy string `json:"policy"`
}

func policyUpdateHandler(w http.ResponseWriter, r *http.Request) {
	log.Warning("Hashed key change request detected!")
	if r.Method != "POST" {
		doJSONWrite(w, 405, createError("Method not supported"))
		return
	}

	var policRecord PolicyUpdateObj
	if err := json.NewDecoder(r.Body).Decode(&policRecord); err != nil {
		decodeFail := APIStatusMessage{"error", "Couldn't decode instruction"}
		responseMessage, _ := json.Marshal(&decodeFail)
		doJSONWrite(w, 400, responseMessage)
		return
	}

	keyName := r.URL.Path[len("/tyk/keys/policy/"):]
	apiID := r.FormValue("api_id")
	responseMessage, code := handleUpdateHashedKey(keyName, apiID, policRecord.Policy)

	doJSONWrite(w, code, responseMessage)
}

func handleUpdateHashedKey(keyName, apiID, policyId string) ([]byte, int) {
	sessionManager := FallbackKeySesionManager
	if apiID != "" {
		spec := GetSpecForApi(apiID)
		if spec != nil {
			sessionManager = spec.SessionManager
		}
	}

	// This is so we bypass the hash function
	sessStore := sessionManager.GetStore()

	// TODO: This is pretty ugly
	setKeyName := "apikey-" + keyName
	rawSessionData, err := sessStore.GetRawKey(setKeyName)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    keyName,
			"status": "fail",
			"err":    err,
		}).Error("Failed to update hashed key.")

		notFound := APIStatusMessage{"error", "Key not found"}
		responseMessage, _ := json.Marshal(&notFound)
		return responseMessage, 400
	}

	sess := SessionState{}
	if err := json.Unmarshal([]byte(rawSessionData), &sess); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    keyName,
			"status": "fail",
			"err":    err,
		}).Error("Failed to update hashed key.")

		notFound := APIStatusMessage{"error", "Unmarshalling failed"}
		responseMessage, _ := json.Marshal(&notFound)
		return responseMessage, 400
	}

	// Set the policy
	sess.LastUpdated = strconv.Itoa(int(time.Now().Unix()))
	sess.ApplyPolicyID = policyId

	sessAsJS, err := json.Marshal(sess)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    keyName,
			"status": "fail",
			"err":    err,
		}).Error("Failed to update hashed key.")

		notFound := APIStatusMessage{"error", "Marshalling failed"}
		responseMessage, _ := json.Marshal(&notFound)
		return responseMessage, 400
	}

	if err := sessStore.SetRawKey(setKeyName, string(sessAsJS), 0); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    keyName,
			"status": "fail",
			"err":    err,
		}).Error("Failed to update hashed key.")

		notFound := APIStatusMessage{"error", "Could not write key data"}
		responseMessage, _ := json.Marshal(&notFound)
		return responseMessage, 400
	}

	statusObj := APIModifyKeySuccess{keyName, "ok", "updated"}
	responseMessage, err := json.Marshal(&statusObj)
	if err != nil {
		log.Error("Marshalling failed: ", err)
		return systemError, 500
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    keyName,
		"status": "ok",
	}).Info("Updated hashed key.")

	return responseMessage, 200
}

func orgHandler(w http.ResponseWriter, r *http.Request) {
	keyName := r.URL.Path[len("/tyk/org/keys/"):]
	filter := r.FormValue("filter")
	var responseMessage []byte
	var code int

	switch r.Method {
	case "POST", "PUT":
		responseMessage, code = handleOrgAddOrUpdate(keyName, r)

	case "GET":

		if keyName != "" {
			// Return single org detail
			responseMessage, code = handleGetOrgDetail(keyName)
		} else {
			// Return list of keys
			responseMessage, code = handleGetAllOrgKeys(filter, "")
		}

	case "DELETE":
		// Remove a key
		responseMessage, code = handleDeleteOrgKey(keyName)

	default:
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	doJSONWrite(w, code, responseMessage)
}

func handleOrgAddOrUpdate(keyName string, r *http.Request) ([]byte, int) {
	var newSession SessionState

	if err := json.NewDecoder(r.Body).Decode(&newSession); err != nil {
		log.Error("Couldn't decode new session object: ", err)
		return createError("Request malformed"), 400
	}
	// Update our session object (create it)

	spec := GetSpecForOrg(keyName)
	var sessionManager SessionHandler

	if spec == nil {
		log.Warning("Couldn't find org session store in active API list")
		if config.SupressDefaultOrgStore {
			return createError("No such organisation found in Active API list"), 400
		}
		sessionManager = &DefaultOrgStore
	} else {
		sessionManager = spec.OrgSessionManager
	}

	if r.FormValue("reset_quota") == "1" {
		sessionManager.ResetQuota(keyName, newSession)
		newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
		rawKey := QuotaKeyPrefix + publicHash(keyName)

		// manage quotas separately
		DefaultQuotaStore.RemoveSession(rawKey)
	}

	err := sessionManager.UpdateSession(keyName, newSession, 0)
	if err != nil {
		return createError("Error writing to key store " + err.Error()), 400
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

	response := APIModifyKeySuccess{
		keyName,
		"ok",
		action,
	}

	responseMessage, err := json.Marshal(&response)
	if err != nil {
		log.Error("Could not create response message: ", err)
		return systemError, 500
	}

	return responseMessage, 200
}

func handleGetOrgDetail(orgID string) ([]byte, int) {
	success := true
	var responseMessage []byte
	var err error

	spec := GetSpecForOrg(orgID)
	if spec == nil {
		notFound := APIStatusMessage{"error", "Org not found"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 400
	}

	session, ok := spec.OrgSessionManager.GetSessionDetail(orgID)
	if !ok {
		success = false
	} else {
		responseMessage, err = json.Marshal(&session)
		if err != nil {
			log.Error("Marshalling failed: ", err)
			success = false
		}
	}

	if !success {
		notFound := APIStatusMessage{"error", "Org not found"}
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"org":    orgID,
			"status": "fail",
			"err":    "not found",
		}).Error("Failed retrieval of record for ORG ID.")
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 404
	}
	log.WithFields(logrus.Fields{
		"prefix": "api",
		"org":    orgID,
		"status": "ok",
	}).Info("Retrieved record for ORG ID.")
	return responseMessage, 200
}

func handleGetAllOrgKeys(filter, orgID string) ([]byte, int) {
	spec := GetSpecForOrg(orgID)
	if spec == nil {
		notFound := APIStatusMessage{"error", "ORG not found"}
		responseMessage, _ := json.Marshal(&notFound)
		return responseMessage, 400
	}

	sessions := spec.OrgSessionManager.GetSessions(filter)
	fixed_sessions := make([]string, 0)
	for _, s := range sessions {
		if !strings.Contains(s, QuotaKeyPrefix) && !strings.Contains(s, RateLimitKeyPrefix) {
			fixed_sessions = append(fixed_sessions, s)
		}
	}
	sessionsObj := APIAllKeys{fixed_sessions}

	responseMessage, err := json.Marshal(&sessionsObj)
	if err != nil {
		log.Error("Marshalling failed: ", err)
		return systemError, 500
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"org":    orgID,
		"status": "ok",
	}).Info("Successful orgs retrieval.")
	return responseMessage, 200
}

func handleDeleteOrgKey(orgID string) ([]byte, int) {
	spec := GetSpecForOrg(orgID)
	if spec == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    orgID,
			"status": "fail",
			"err":    "not found",
		}).Error("Failed to delete org key.")

		notFound := APIStatusMessage{"error", "Org not found"}
		responseMessage, _ := json.Marshal(&notFound)
		return responseMessage, 400
	}

	spec.OrgSessionManager.RemoveSession(orgID)

	statusObj := APIModifyKeySuccess{orgID, "ok", "deleted"}
	responseMessage, err := json.Marshal(&statusObj)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"key":    orgID,
			"status": "fail",
			"err":    err,
		}).Error("Failed to delete org key.")

		return systemError, 500
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    orgID,
		"status": "ok",
	}).Info("Org key deleted.")

	return responseMessage, 200
}

func groupResetHandler(w http.ResponseWriter, r *http.Request) {
	var responseMessage []byte
	var code int

	if r.Method == "GET" {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"status": "ok",
		}).Info("Group reload accepted.")

		responseMessage, code = signalGroupReload()

	} else {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"status": "fail",
			"err":    "wrong method",
		}).Error("Group reload failed.")
		code = 405
		responseMessage = createError("Method not supported")
	}

	doJSONWrite(w, code, responseMessage)
}

func resetHandler(fn func()) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var responseMessage []byte
		var code int

		if r.Method == "GET" {
			responseMessage, code = handleURLReload(fn)
		} else {
			code = 405
			responseMessage = createError("Method not supported")
		}

		doJSONWrite(w, code, responseMessage)
	}
}

func createKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"status": "fail",
			"method": r.Method,
		}).Warning("Attempted to create key with wrong HTTP method.")
		doJSONWrite(w, 405, createError("Method not supported"))
		return
	}

	var newSession SessionState
	if err := json.NewDecoder(r.Body).Decode(&newSession); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"status": "fail",
			"err":    err,
		}).Error("Key creation failed.")
		doJSONWrite(w, 500, systemError)
		return
	}

	newKey := keyGen.GenerateAuthKey(newSession.OrgID)
	if newSession.HMACEnabled {
		newSession.HmacSecret = keyGen.GenerateHMACSecret()
	}

	newSession.LastUpdated = strconv.Itoa(int(time.Now().Unix()))

	if len(newSession.AccessRights) > 0 {
		for apiID := range newSession.AccessRights {
			apiSpec := GetSpecForApi(apiID)
			if apiSpec != nil {
				checkAndApplyTrialPeriod(newKey, apiID, &newSession)
				// If we have enabled HMAC checking for keys, we need to generate a secret for the client to use
				if !apiSpec.DontSetQuotasOnCreate {
					// Reset quota by default
					apiSpec.SessionManager.ResetQuota(newKey, newSession)
					newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
				}
				err := apiSpec.SessionManager.UpdateSession(newKey, newSession, getLifetime(apiSpec, &newSession))
				if err != nil {
					responseMessage := createError("Failed to create key - " + err.Error())
					doJSONWrite(w, 403, responseMessage)
					return
				}
			} else {
				// Use fallback
				sessionManager := FallbackKeySesionManager
				newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
				sessionManager.ResetQuota(newKey, newSession)
				err := sessionManager.UpdateSession(newKey, newSession, -1)
				if err != nil {
					responseMessage := createError("Failed to create key - " + err.Error())
					doJSONWrite(w, 403, responseMessage)
					return
				}
			}
		}
	} else {
		if config.AllowMasterKeys {
			// nothing defined, add key to ALL
			log.WithFields(logrus.Fields{
				"prefix":      "api",
				"status":      "warning",
				"org_id":      newSession.OrgID,
				"api_id":      "--",
				"user_id":     "system",
				"user_ip":     requestAddrs(r),
				"path":        "--",
				"server_name": "system",
			}).Warning("No API Access Rights set on key session, adding key to all APIs.")

			for _, spec := range ApiSpecRegister {
				checkAndApplyTrialPeriod(newKey, spec.APIID, &newSession)
				if !spec.DontSetQuotasOnCreate {
					// Reset quote by default
					spec.SessionManager.ResetQuota(newKey, newSession)
					newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
				}
				err := spec.SessionManager.UpdateSession(newKey, newSession, getLifetime(spec, &newSession))
				if err != nil {
					responseMessage := createError("Failed to create key - " + err.Error())
					doJSONWrite(w, 403, responseMessage)
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
				"user_ip":     requestAddrs(r),
				"path":        "--",
				"server_name": "system",
			}).Error("Master keys disallowed in configuration, key not added.")

			responseMessage := createError("Failed to create key, keys must have at least one Access Rights record set.")
			doJSONWrite(w, 403, responseMessage)
			return
		}

	}

	responseObj := APIModifyKeySuccess{
		Action: "create",
		Key:    newKey,
		Status: "ok",
	}
	responseMessage, err := json.Marshal(&responseObj)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "api",
			"status":      "error",
			"err":         err,
			"org_id":      newSession.OrgID,
			"api_id":      "--",
			"user_id":     "system",
			"user_ip":     requestAddrs(r),
			"path":        "--",
			"server_name": "system",
		}).Error("System error, failed to generate key.")

		doJSONWrite(w, 500, systemError)
		return
	}

	FireSystemEvent(EventTokenCreated, EventTokenMeta{
		EventMetaDefault: EventMetaDefault{
			Message:            "Key generated.",
			OriginatingRequest: "",
		},
		Org: newSession.OrgID,
		Key: newKey,
	})

	log.WithFields(logrus.Fields{
		"prefix":      "api",
		"key":         ObfuscateKeyString(newKey),
		"status":      "ok",
		"api_id":      "--",
		"org_id":      newSession.OrgID,
		"user_id":     "system",
		"user_ip":     requestAddrs(r),
		"path":        "--",
		"server_name": "system",
	}).Info("Generated new key: (", ObfuscateKeyString(newKey), ")")

	doJSONWrite(w, 200, responseMessage)
}

// NewClientRequest is an outward facing JSON object translated from osin OAuthClients
type NewClientRequest struct {
	ClientID          string `json:"client_id"`
	ClientRedirectURI string `json:"redirect_uri"`
	APIID             string `json:"api_id"`
	PolicyID          string `json:"policy_id"`
	ClientSecret      string `json:"secret"`
}

func createOauthClientStorageID(clientID string) string {
	return prefixClient + clientID
}

func createOauthClient(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		doJSONWrite(w, 405, createError("Method not supported"))
		return
	}
	var newOauthClient NewClientRequest
	if err := json.NewDecoder(r.Body).Decode(&newOauthClient); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"status": "fail",
			"err":    err,
		}).Error("Failed to create OAuth client")
		doJSONWrite(w, 500, systemError)
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

	storageID := createOauthClientStorageID(newClient.GetId())
	log.WithFields(logrus.Fields{
		"prefix": "api",
	}).Debug("Created storage ID: ", storageID)

	apiSpec := GetSpecForApi(newOauthClient.APIID)
	if apiSpec == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  newOauthClient.APIID,
			"status": "fail",
			"err":    "API doesn't exist",
		}).Error("Failed to create OAuth client")
	}

	err := apiSpec.OAuthManager.OsinServer.Storage.SetClient(storageID, &newClient, true)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  newOauthClient.APIID,
			"status": "fail",
			"err":    err,
		}).Error("Failed to create OAuth client")
		doJSONWrite(w, 500, createError("Failure in storing client data."))
		return
	}

	reportableClientData := NewClientRequest{
		ClientID:          newClient.GetId(),
		ClientSecret:      newClient.GetSecret(),
		ClientRedirectURI: newClient.GetRedirectUri(),
		PolicyID:          newClient.GetPolicyID(),
	}

	responseMessage, err := json.Marshal(&reportableClientData)
	if err != nil {
		log.Error("Marshalling failed: ", err)
		doJSONWrite(w, 500, systemError)
		return
	}
	log.WithFields(logrus.Fields{
		"prefix":            "api",
		"apiID":             newOauthClient.APIID,
		"clientID":          reportableClientData.ClientID,
		"clientRedirectURI": reportableClientData.ClientRedirectURI,
		"status":            "ok",
	}).Info("Created OAuth client")

	doJSONWrite(w, 200, responseMessage)
}

func invalidateOauthRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		doJSONWrite(w, 405, createError("Method not supported"))
		return
	}
	apiID := r.FormValue("api_id")
	if apiID == "" {
		doJSONWrite(w, 400, createError("Missing parameter api_id"))
		return
	}
	apiSpec := GetSpecForApi(apiID)

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

		doJSONWrite(w, 400, createError("API for this refresh token not found"))
		return
	}

	if apiSpec.OAuthManager == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    "API is not OAuth",
		}).Error("Failed to invalidate refresh token")

		doJSONWrite(w, 400, createError("OAuth is not enabled on this API"))
		return
	}

	keyCombined := r.URL.Path[len("/tyk/oauth/refresh/"):]
	err := apiSpec.OAuthManager.OsinServer.Storage.RemoveRefresh(keyCombined)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    err,
		}).Error("Failed to invalidate refresh token")

		doJSONWrite(w, 400, createError("Failed to invalidate refresh token"))
		return
	}

	success := APIModifyKeySuccess{
		Key:    keyCombined,
		Status: "ok",
		Action: "deleted",
	}

	responseMessage, err := json.Marshal(&success)

	if err != nil {
		log.Error(err)
		doJSONWrite(w, 400, createError("Failed to marshal data"))
		return
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
		"token":  keyCombined,
		"status": "ok",
	}).Info("Invalidated refresh token")

	doJSONWrite(w, 200, responseMessage)
}

func oAuthClientHandler(w http.ResponseWriter, r *http.Request) {
	keyCombined := r.URL.Path[len("/tyk/oauth/clients/"):]
	var responseMessage []byte
	var code int

	keyName := ""
	apiID := ""

	parts := strings.Split(keyCombined, "/")
	switch len(parts) {
	case 2:
		keyName = parts[1]
		apiID = parts[0]
	case 1:
		apiID = parts[0]
	default:
		doJSONWrite(w, 405, createError("Method not supported"))
		return
	}

	switch r.Method {
	case "GET":
		if keyName != "" {
			// Return single client detail
			responseMessage, code = getOauthClientDetails(keyName, apiID)
		} else {
			// Return list of keys
			responseMessage, code = getOauthClients(apiID)
		}
	case "DELETE":
		// Remove a key
		responseMessage, code = handleDeleteOAuthClient(keyName, apiID)
	default:
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	doJSONWrite(w, code, responseMessage)
}

// Get client details
func getOauthClientDetails(keyName, apiID string) ([]byte, int) {
	success := true
	var responseMessage []byte
	var err error

	storageID := createOauthClientStorageID(keyName)
	apiSpec := GetSpecForApi(apiID)
	if apiSpec == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"client": keyName,
			"err":    "not found",
		}).Error("Failed to retrieve OAuth client details")
		notFound := APIStatusMessage{"error", "OAuth Client ID not found"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 404
	}

	clientData, err := apiSpec.OAuthManager.OsinServer.Storage.GetClientNoPrefix(storageID)
	if err != nil {
		success = false
	} else {
		reportableClientData := NewClientRequest{
			ClientID:          clientData.GetId(),
			ClientSecret:      clientData.GetSecret(),
			ClientRedirectURI: clientData.GetRedirectUri(),
			PolicyID:          clientData.GetPolicyID(),
		}
		responseMessage, err = json.Marshal(&reportableClientData)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "api",
				"apiID":  apiID,
				"status": "fail",
				"client": keyName,
				"err":    err,
			}).Error("Failed to report OAuth client details")
			success = false
		}
	}

	if !success {
		notFound := APIStatusMessage{"error", "OAuth Client ID not found"}
		responseMessage, _ := json.Marshal(&notFound)
		return responseMessage, 404
	}
	log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
		"status": "ok",
		"client": keyName,
	}).Info("Retrieved OAuth client ID")

	return responseMessage, 200
}

// Delete Client
func handleDeleteOAuthClient(keyName, apiID string) ([]byte, int) {
	var responseMessage []byte

	storageID := createOauthClientStorageID(keyName)

	apiSpec := GetSpecForApi(apiID)
	if apiSpec == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"client": keyName,
			"err":    "not found",
		}).Error("Failed to delete OAuth client")

		notFound := APIStatusMessage{"error", "OAuth Client ID not found"}
		responseMessage, _ = json.Marshal(&notFound)

		return responseMessage, 400
	}

	err := apiSpec.OAuthManager.OsinServer.Storage.DeleteClient(storageID, true)
	if err != nil {
		errObj := APIErrorMessage{"error", "Delete failed"}
		responseMessage, _ = json.Marshal(&errObj)
		return responseMessage, 500
	}

	statusObj := APIModifyKeySuccess{keyName, "ok", "deleted"}
	responseMessage, err = json.Marshal(&statusObj)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"client": keyName,
			"err":    err,
		}).Error("Failed to report OAuth delete success")
		return systemError, 500
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
		"status": "ok",
		"client": keyName,
	}).Info("Deleted OAuth client")

	return responseMessage, 200
}

// List Clients
func getOauthClients(apiID string) ([]byte, int) {
	success := true
	var responseMessage []byte
	var err error

	filterID := prefixClient

	apiSpec := GetSpecForApi(apiID)
	if apiSpec == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    "API not found",
		}).Error("Failed to retrieve OAuth client list.")

		notFound := APIStatusMessage{"error", "OAuth Client ID not found"}
		responseMessage, _ = json.Marshal(&notFound)

		return responseMessage, 400
	}

	if apiSpec.OAuthManager == nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    "API not found",
		}).Error("Failed to retrieve OAuth client list.")

		notAvailable := APIStatusMessage{"error", "OAuth client list isn't available or hasn't been propagated yet."}
		responseMessage, _ = json.Marshal(&notAvailable)

		return responseMessage, 400
	}

	clientData, err := apiSpec.OAuthManager.OsinServer.Storage.GetClients(filterID, true)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"apiID":  apiID,
			"status": "fail",
			"err":    err,
		}).Error("Failed to report OAuth client list")

		success = false
	} else {
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

		responseMessage, err = json.Marshal(&clients)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "api",
				"apiID":  apiID,
				"status": "fail",
				"err":    err,
			}).Error("Failed to report OAuth client list")
			success = false
		}
	}

	if !success {
		notFound := APIStatusMessage{"error", "OAuth slients not found"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 404
	}
	log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
		"status": "ok",
	}).Info("Retrieved OAuth client list")

	return responseMessage, 200
}

func healthCheckhandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		doJSONWrite(w, 405, createError("Method not supported"))
		return
	}
	if !config.HealthCheck.EnableHealthChecks {
		doJSONWrite(w, 405, createError("Health checks are not enabled for this node"))
		return
	}
	apiID := r.FormValue("api_id")
	if apiID == "" {
		doJSONWrite(w, 405, createError("missing api_id parameter"))
		return
	}
	apiSpec := GetSpecForApi(apiID)
	if apiSpec == nil {
		doJSONWrite(w, 405, createError("API ID not found"))
		return
	}
	health, _ := apiSpec.Health.GetApiHealthValues()
	responseMessage, err := json.Marshal(health)
	if err != nil {
		doJSONWrite(w, 405, createError("Failed to encode data"))
		return
	}
	doJSONWrite(w, 200, responseMessage)
}

func UserRatesCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionState := context.Get(r, SessionData)
		if sessionState == nil {
			responseMessage := createError("Health checks are not enabled for this node")
			doJSONWrite(w, 405, responseMessage)
			return
		}

		userSession := sessionState.(SessionState)
		returnSession := PublicSessionState{}
		returnSession.Quota.QuotaRenews = userSession.QuotaRenews
		returnSession.Quota.QuotaRemaining = userSession.QuotaRemaining
		returnSession.Quota.QuotaMax = userSession.QuotaMax
		returnSession.RateLimit.Rate = userSession.Rate
		returnSession.RateLimit.Per = userSession.Per

		responseMessage, err := json.Marshal(returnSession)
		if err != nil {
			responseMessage = createError("Failed to encode data")
			doJSONWrite(w, 405, responseMessage)
			return
		}

		doJSONWrite(w, 200, responseMessage)
	}
}

func invalidateCacheHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		doJSONWrite(w, 405, createError("Method not supported"))
		return
	}
	apiID := r.URL.Path[len("/tyk/cache/"):]

	spec := GetSpecForApi(apiID)
	var orgid string
	if spec != nil {
		orgid = spec.OrgID
	}

	if err := handleInvalidateAPICache(apiID); err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "api",
			"api_id":      apiID,
			"status":      "fail",
			"err":         err,
			"org_id":      orgid,
			"user_id":     "system",
			"user_ip":     requestAddrs(r),
			"path":        "--",
			"server_name": "system",
		}).Error("Failed to delete cache: ", err)

		doJSONWrite(w, 500, createError("Cache invalidation failed"))
		return
	}

	okMsg := APIStatusMessage{"ok", "cache invalidated"}
	responseMessage, _ := json.Marshal(&okMsg)
	log.WithFields(logrus.Fields{
		"prefix":      "api",
		"status":      "ok",
		"org_id":      orgid,
		"api_id":      apiID,
		"user_id":     "system",
		"user_ip":     requestAddrs(r),
		"path":        "--",
		"server_name": "system",
	}).Info("Cache invalidated successfully")

	doJSONWrite(w, 200, responseMessage)
}

func handleInvalidateAPICache(apiID string) error {
	keyPrefix := "cache-" + strings.Replace(apiID, "/", "", -1)
	matchPattern := keyPrefix + "*"
	store := getGlobalLocalCacheStorageHandler(keyPrefix, false)

	if ok := store.DeleteScanMatch(matchPattern); !ok {
		return errors.New("scan/delete failed")
	}
	return nil
}
