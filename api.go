package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	osin "github.com/lonelycode/osin"
	"github.com/lonelycode/tykcommon"
	"github.com/nu7hatch/gouuid"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
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

func DoJSONWrite(w http.ResponseWriter, code int, responseMessage []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, string(responseMessage))
}

func GetSpecForApi(APIID string) *APISpec {
	spec, ok := ApiSpecRegister[APIID]
	if !ok {
		return nil
	}

	return spec
}

func GetSpecForOrg(APIID string) *APISpec {
	var aKey string
	for k, v := range ApiSpecRegister {
		if v.OrgID == APIID {
			return v
		}
		aKey = k
	}

	// If we can't find a spec, it doesn;t matter, because we default to Redis anyway, grab whatever you can find
	return ApiSpecRegister[aKey]
}

func checkAndApplyTrialPeriod(keyName string, apiId string, newSession *SessionState) {
	// Check the policy to see if we are forcing an expiry on the key
	if newSession.ApplyPolicyID != "" {
		thisPolicy, foundPolicy := Policies[newSession.ApplyPolicyID]
		if foundPolicy {
			// Are we foring an expiry?
			if thisPolicy.KeyExpiresIn > 0 {
				// We are, does the key exist?
				_, found := GetKeyDetail(keyName, apiId)
				if !found {
					// this is a new key, lets expire it
					newSession.Expires = time.Now().Unix() + thisPolicy.KeyExpiresIn
				}

			}
		}
	}
}

func doAddOrUpdate(keyName string, newSession SessionState, dontReset bool) error {
	if len(newSession.AccessRights) > 0 {
		// We have a specific list of access rules, only add / update those
		for apiId, _ := range newSession.AccessRights {
			thisAPISpec := GetSpecForApi(apiId)
			if thisAPISpec != nil {

				checkAndApplyTrialPeriod(keyName, apiId, &newSession)

				// Lets reset keys if they are edited by admin
				if !thisAPISpec.DontSetQuotasOnCreate {
					// Reset quote by default
					if !dontReset {
						thisAPISpec.SessionManager.ResetQuota(keyName, newSession)
						newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
					}

					err := thisAPISpec.SessionManager.UpdateSession(keyName, newSession, thisAPISpec.SessionLifetime)
					if err != nil {
						return err
					}
				}
			} else {
				log.WithFields(logrus.Fields{
					"key":   keyName,
					"apiID": apiId,
				}).Error("Could not add key for this API ID, API doesn't exist.")
				return errors.New("API must be active to add keys")
			}
		}
	} else {
		// nothing defined, add key to ALL
		if config.AllowMasterKeys {
			log.Warning("No API Access Rights set, adding key to ALL.")
			for _, spec := range ApiSpecRegister {
				if !dontReset {
					spec.SessionManager.ResetQuota(keyName, newSession)
					newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
				}
				checkAndApplyTrialPeriod(keyName, spec.APIID, &newSession)
				err := spec.SessionManager.UpdateSession(keyName, newSession, spec.SessionLifetime)
				if err != nil {
					return err
				}
			}
		} else {
			log.Error("Master keys disallowed in configuration, key not added.")
			return errors.New("Master keys not allowed")
		}

	}

	log.WithFields(logrus.Fields{
		"key":     keyName,
		"expires": newSession.Expires,
	}).Debug("New key added or updated.")
	return nil
}

// ---- TODO: This changes the URL structure of the API completely ----
// ISSUE: If Session stores are stored with API specs, then managing keys will need to be done per store, i.e. add to all stores,
// remove from all stores, update to all stores, stores handle quotas separately though because they are localised! Keys will
// need to be managed by API, but only for GetDetail, GetList, UpdateKey and DeleteKey

func SetSessionPassword(session *SessionState) {
	session.BasicAuthData.Hash = HASH_BCrypt
	newPass, err := bcrypt.GenerateFromPassword([]byte(session.BasicAuthData.Password), 10)
	if err != nil {
		log.Error("Could not hash password, setting to plaintext, error was: ", err)
		session.BasicAuthData.Hash = HASH_PlainText
		return
	}

	session.BasicAuthData.Password = string(newPass)
}

func GetKeyDetail(key string, APIID string) (SessionState, bool) {
	thiSpec := GetSpecForApi(APIID)
	if thiSpec == nil {
		log.Error("No API Spec found for this keyspace")
		return SessionState{}, false
	}

	return thiSpec.SessionManager.GetSessionDetail(key)
}

func handleAddOrUpdate(keyName string, r *http.Request) ([]byte, int) {
	success := true
	decoder := json.NewDecoder(r.Body)
	var responseMessage []byte
	var newSession SessionState
	err := decoder.Decode(&newSession)
	code := 200

	if err != nil {
		log.Error("Couldn't decode new session object: ", err)
		code = 400
		success = false
		responseMessage = createError("Request malformed")
	} else {
		// DO ADD OR UPDATE
		// Update our session object (create it)
		if newSession.BasicAuthData.Password != "" {
			// If we are using a basic auth user, then we need to make the keyname explicit against the OrgId in order to differentiate it
			// Only if it's NEW
			if r.Method == "POST" {
				keyName = newSession.OrgID + keyName
				// It's a create, so lets hash the password
				SetSessionPassword(&newSession)
			}

			if r.Method == "PUT" {
				// Ge the session
				var originalKey SessionState
				var found bool
				for api_id, _ := range newSession.AccessRights {
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
		dont_reset := r.FormValue("suppress_reset")
		var suppress_reset bool = false

		if dont_reset == "1" {
			suppress_reset = true
		}
		addUpdateErr := doAddOrUpdate(keyName, newSession, suppress_reset)
		if addUpdateErr != nil {
			success = false
			responseMessage = createError("Failed to create key, ensure security settings are correct.")
		}
	}

	var action string
	if r.Method == "POST" {
		action = "added"
	} else {
		action = "modified"
	}

	if success {
		response := APIModifyKeySuccess{
			keyName,
			"ok",
			action}

		responseMessage, err = json.Marshal(&response)

		if err != nil {
			log.Error("Could not create response message: ", err)
			code = 500
			responseMessage = []byte(E_SYSTEM_ERROR)
		}
	}

	return responseMessage, code
}

func handleGetDetail(sessionKey string, APIID string) ([]byte, int) {
	success := true
	var responseMessage []byte
	var err error
	code := 200

	thiSpec := GetSpecForApi(APIID)
	if thiSpec == nil {
		notFound := APIStatusMessage{"error", "API not found"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 400
	}

	thisSession, ok := thiSpec.SessionManager.GetSessionDetail(sessionKey)
	if !ok {
		success = false
	} else {
		responseMessage, err = json.Marshal(&thisSession)
		if err != nil {
			log.Error("Marshalling failed: ", err)
			success = false
		}
	}

	if !success {
		notFound := APIStatusMessage{"error", "Key not found"}
		responseMessage, _ = json.Marshal(&notFound)
		code = 404
		log.WithFields(logrus.Fields{
			"key": sessionKey,
		}).Warning("Attempted key retrieval - failure.")
	} else {
		log.WithFields(logrus.Fields{
			"key": sessionKey,
		}).Debug("Attempted key retrieval - success.")
	}

	return responseMessage, code
}

// APIAllKeys represents a list of keys in the memory store
type APIAllKeys struct {
	APIKeys []string `json:"keys"`
}

func handleGetAllKeys(filter string, APIID string) ([]byte, int) {
	success := true
	var responseMessage []byte
	code := 200

	var err error

	thiSpec := GetSpecForApi(APIID)
	if thiSpec == nil {
		notFound := APIStatusMessage{"error", "API not found"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 400
	}

	sessions := thiSpec.SessionManager.GetSessions(filter)

	fixed_sessions := make([]string, 0)
	for _, s := range sessions {
		if !strings.Contains(s, QuotaKeyPrefix) {
			if !strings.Contains(s, RateLimitKeyPrefix) {
				fixed_sessions = append(fixed_sessions, s)
			}
		}
	}

	sessionsObj := APIAllKeys{fixed_sessions}

	responseMessage, err = json.Marshal(&sessionsObj)
	if err != nil {
		log.Error("Marshalling failed: ", err)
		success = false
		code = 500
	}

	if success {
		return responseMessage, code
	}

	log.Debug("Attempted keys retrieval - success.")
	return []byte(E_SYSTEM_ERROR), code

}

// APIStatusMessage represents an API status message
type APIStatusMessage struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func handleDeleteKey(keyName string, APIID string) ([]byte, int) {
	var responseMessage []byte
	var err error

	if APIID == "-1" {
		// Go through ALL managed API's and delete the key
		for _, spec := range ApiSpecRegister {
			spec.SessionManager.RemoveSession(keyName)
		}

		log.WithFields(logrus.Fields{
			"key": keyName,
		}).Debug("Attempted key deletion across all managed API's - success.")

		return responseMessage, 200
	}

	thiSpec := GetSpecForApi(APIID)
	if thiSpec == nil {
		notFound := APIStatusMessage{"error", "API not found"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 400
	}

	thiSpec.SessionManager.RemoveSession(keyName)
	code := 200

	statusObj := APIModifyKeySuccess{keyName, "ok", "deleted"}
	responseMessage, err = json.Marshal(&statusObj)

	if err != nil {
		log.Error("Marshalling failed: ", err)
		return []byte(E_SYSTEM_ERROR), 500
	}

	log.WithFields(logrus.Fields{
		"key": keyName,
	}).Debug("Attempted key deletion - success.")

	return responseMessage, code
}

func handleDeleteHashedKey(keyName string, APIID string) ([]byte, int) {
	var responseMessage []byte
	var err error

	if APIID == "-1" {
		// Go through ALL managed API's and delete the key
		for _, spec := range ApiSpecRegister {
			spec.SessionManager.RemoveSession(keyName)
		}

		log.WithFields(logrus.Fields{
			"key": keyName,
		}).Debug("Attempted key deletion across all managed API's - success.")

		return responseMessage, 200
	}

	thiSpec := GetSpecForApi(APIID)
	if thiSpec == nil {
		notFound := APIStatusMessage{"error", "API not found"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 400
	}

	// This is so we bypass the hash function
	sessStore := thiSpec.SessionManager.GetStore()
	// TODO: This is pretty ugly
	setKeyName := "apikey-" + keyName
	sessStore.DeleteRawKey(setKeyName)
	code := 200

	statusObj := APIModifyKeySuccess{keyName, "ok", "deleted"}
	responseMessage, err = json.Marshal(&statusObj)

	if err != nil {
		log.Error("Marshalling failed: ", err)
		return []byte(E_SYSTEM_ERROR), 500
	}

	log.WithFields(logrus.Fields{
		"key": keyName,
	}).Debug("Attempted key deletion - success.")

	return responseMessage, code
}

func handleURLReload() ([]byte, int) {
	var responseMessage []byte
	var err error

	ReloadURLStructure()

	code := 200

	statusObj := APIErrorMessage{"ok", ""}
	responseMessage, err = json.Marshal(&statusObj)

	if err != nil {
		log.Error("Marshalling failed: ", err)
		return []byte(E_SYSTEM_ERROR), 500
	}

	log.WithFields(logrus.Fields{}).Info("Reloaded URL Structure - Success")

	return responseMessage, code
}

func signalGroupReload() ([]byte, int) {
	var responseMessage []byte
	var err error

	notice := Notification{
		Command: NoticeGroupReload,
	}

	// Signal to the group via redis
	MainNotifier.Notify(notice)

	code := 200

	statusObj := APIErrorMessage{"ok", ""}
	responseMessage, err = json.Marshal(&statusObj)

	if err != nil {
		log.Error("Marshalling failed: ", err)
		return []byte(E_SYSTEM_ERROR), 500
	}

	log.WithFields(logrus.Fields{}).Info("Reloaded URL Structure - Success")

	return responseMessage, code
}

func HandleGetAPIList() ([]byte, int) {
	var responseMessage []byte
	var err error

	var thisAPIIDList []tykcommon.APIDefinition
	thisAPIIDList = make([]tykcommon.APIDefinition, len(ApiSpecRegister))

	c := 0
	for _, apiSpec := range ApiSpecRegister {
		thisAPIIDList[c] = apiSpec.APIDefinition
		thisAPIIDList[c].RawData = nil
		c++
	}

	responseMessage, err = json.Marshal(&thisAPIIDList)

	if err != nil {
		log.Error("Marshalling failed: ", err)
		return []byte(E_SYSTEM_ERROR), 500
	}

	return responseMessage, 200
}

func HandleGetAPI(APIID string) ([]byte, int) {
	var responseMessage []byte
	var err error

	for _, apiSpec := range ApiSpecRegister {
		if apiSpec.APIDefinition.APIID == APIID {

			responseMessage, err = json.Marshal(apiSpec.APIDefinition)

			if err != nil {
				log.Error("Marshalling failed: ", err)
				return []byte(E_SYSTEM_ERROR), 500
			}

			return responseMessage, 200
		}
	}

	log.WithFields(logrus.Fields{
		"apiID": APIID,
	}).Error("API doesn't exist.")
	notFound := APIStatusMessage{"error", "API not found"}
	responseMessage, _ = json.Marshal(&notFound)
	code := 404
	return responseMessage, code
}

func HandleAddOrUpdateApi(APIID string, r *http.Request) ([]byte, int) {
	success := true
	decoder := json.NewDecoder(r.Body)
	var responseMessage []byte
	var newDef tykcommon.APIDefinition
	err := decoder.Decode(&newDef)
	code := 200

	if err != nil {
		log.Error("Couldn't decode new API Definition object: ", err)
		success = false
		return createError("Request malformed"), 400
	}

	if APIID != "" {
		if newDef.APIID != APIID {
			log.Error("PUT operation on different APIIDs")
			return createError("Request APIID does not match that in Definition! For Updtae operations these must match."), 400
		}
	}

	// Create a filename
	defFilename := newDef.APIID + ".json"
	defFilePath := path.Join(config.AppPath, defFilename)

	// If it exists, delete it
	if _, err := os.Stat(defFilePath); err == nil {
		log.Warning("API Definition with this ID already exists, deleting file...")
		os.Remove(defFilePath)
	}

	// unmarshal the object into the file
	asByte, mErr := json.MarshalIndent(newDef, "", "  ")
	if mErr != nil {
		log.Error("Marshalling of API Definition failed: ", mErr)
		return createError("Marshalling failed"), 500
	}

	wErr := ioutil.WriteFile(defFilePath, asByte, 0644)
	if wErr != nil {
		log.Error("Failed to create file! - ", wErr)
		success = false
		return createError("File object creation failed, write error"), 500
	}

	var action string
	if r.Method == "POST" {
		action = "added"
	} else {
		action = "modified"
	}

	if success {
		response := APIModifyKeySuccess{
			newDef.APIID,
			"ok",
			action}

		responseMessage, err = json.Marshal(&response)

		if err != nil {
			log.Error("Could not create response message: ", err)
			code = 500
			responseMessage = []byte(E_SYSTEM_ERROR)
		}
	}

	return responseMessage, code
}

func HandleDeleteAPI(APIID string) ([]byte, int) {
	success := true
	var responseMessage []byte
	code := 200

	// Generate a filename
	defFilename := APIID + ".json"
	defFilePath := path.Join(config.AppPath, defFilename)

	// If it exists, delete it
	if _, err := os.Stat(defFilePath); err != nil {
		log.Warning("File does not exist! ", err)
		return createError("Delete failed"), 500
	}

	os.Remove(defFilePath)

	if success {
		response := APIModifyKeySuccess{
			APIID,
			"ok",
			"deleted"}

		var err error
		responseMessage, err = json.Marshal(&response)

		if err != nil {
			log.Error("Could not create response message: ", err)
			code = 500
			responseMessage = []byte(E_SYSTEM_ERROR)
		}
	}

	return responseMessage, code
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	APIID := r.URL.Path[len("/tyk/apis/"):]
	var responseMessage []byte
	var code int

	log.Debug(r.Method)
	if r.Method == "GET" {
		if APIID != "" {
			log.Debug("Requesting API definition for", APIID)
			responseMessage, code = HandleGetAPI(APIID)
		} else {
			log.Debug("Requesting API list")
			responseMessage, code = HandleGetAPIList()
		}

	} else if r.Method == "POST" {
		log.Debug("Creating new definition file")
		responseMessage, code = HandleAddOrUpdateApi(APIID, r)
	} else if r.Method == "PUT" {
		log.Debug("Updating existing API: ", APIID)
		responseMessage, code = HandleAddOrUpdateApi(APIID, r)
	} else if r.Method == "DELETE" {
		log.Debug("Deleting existing API: ", APIID)
		if APIID != "" {
			log.Debug("Deleting API definition for: ", APIID)
			responseMessage, code = HandleDeleteAPI(APIID)
		} else {
			code = 400
			responseMessage = createError("Must specify an APIID to delete")
		}
	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	DoJSONWrite(w, code, responseMessage)
}

func keyHandler(w http.ResponseWriter, r *http.Request) {
	keyName := r.URL.Path[len("/tyk/keys/"):]
	filter := r.FormValue("filter")
	APIID := r.FormValue("api_id")
	var responseMessage []byte
	var code int

	if r.Method == "POST" || r.Method == "PUT" {
		responseMessage, code = handleAddOrUpdate(keyName, r)

	} else if r.Method == "GET" {
		if APIID == "" {
			code = 405
			responseMessage = createError("Missing required parameter 'api_id' in request")
		} else {
			if keyName != "" {
				// Return single key detail
				responseMessage, code = handleGetDetail(keyName, APIID)
			} else {
				// Return list of keys
				responseMessage, code = handleGetAllKeys(filter, APIID)
			}
		}

	} else if r.Method == "DELETE" {
		hashed := r.FormValue("hashed")
		// Remove a key
		if hashed == "" {
			responseMessage, code = handleDeleteKey(keyName, APIID)
		} else {
			responseMessage, code = handleDeleteHashedKey(keyName, APIID)
		}

	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	DoJSONWrite(w, code, responseMessage)
}

type PolicyUpdateObj struct {
	Policy string `json:"policy"`
}

func policyUpdateHandler(w http.ResponseWriter, r *http.Request) {
	log.Warning("Hashed key change request detected!")
	keyName := r.URL.Path[len("/tyk/keys/policy/"):]
	APIID := r.FormValue("api_id")
	var responseMessage []byte
	var code int

	if r.Method == "POST" {
		decoder := json.NewDecoder(r.Body)
		var policRecord PolicyUpdateObj
		err := decoder.Decode(&policRecord)

		if err != nil {
			decodeFail := APIStatusMessage{"error", "Couldn't decode instruction"}
			responseMessage, _ = json.Marshal(&decodeFail)
			DoJSONWrite(w, 400, responseMessage)
			return
		}

		responseMessage, code = handleUpdateHashedKey(keyName, APIID, policRecord.Policy)

	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	DoJSONWrite(w, code, responseMessage)
}

func handleUpdateHashedKey(keyName string, APIID string, policyId string) ([]byte, int) {
	var responseMessage []byte
	var err error

	thiSpec := GetSpecForApi(APIID)
	if thiSpec == nil {
		notFound := APIStatusMessage{"error", "API not found"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 400
	}

	// This is so we bypass the hash function
	sessStore := thiSpec.SessionManager.GetStore()
	// TODO: This is pretty ugly
	setKeyName := "apikey-" + keyName
	rawSessionData, sessErr := sessStore.GetRawKey(setKeyName)

	if sessErr != nil {
		notFound := APIStatusMessage{"error", "Key not found"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 400
	}

	sess := SessionState{}
	jsErr := json.Unmarshal([]byte(rawSessionData), &sess)
	if jsErr != nil {
		notFound := APIStatusMessage{"error", "Unmarshalling failed"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 400
	}

	// Set the policy
	sess.ApplyPolicyID = policyId

	sessAsJS, encErr := json.Marshal(sess)
	if encErr != nil {
		notFound := APIStatusMessage{"error", "Marshalling failed"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 400
	}

	setErr := sessStore.SetRawKey(setKeyName, string(sessAsJS), 0)
	if setErr != nil {
		notFound := APIStatusMessage{"error", "Could not write key data"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 400
	}

	code := 200

	statusObj := APIModifyKeySuccess{keyName, "ok", "updated"}
	responseMessage, err = json.Marshal(&statusObj)

	if err != nil {
		log.Error("Marshalling failed: ", err)
		return []byte(E_SYSTEM_ERROR), 500
	}

	log.WithFields(logrus.Fields{
		"key": keyName,
	}).Debug("Attempted key deletion - success.")

	return responseMessage, code
}

func orgHandler(w http.ResponseWriter, r *http.Request) {
	keyName := r.URL.Path[len("/tyk/org/keys/"):]
	filter := r.FormValue("filter")
	var responseMessage []byte
	var code int

	if r.Method == "POST" || r.Method == "PUT" {
		responseMessage, code = handleOrgAddOrUpdate(keyName, r)

	} else if r.Method == "GET" {

		if keyName != "" {
			// Return single org detail
			responseMessage, code = handleGetOrgDetail(keyName)
		} else {
			// Return list of keys
			responseMessage, code = handleGetAllOrgKeys(filter, "")
		}

	} else if r.Method == "DELETE" {
		// Remove a key
		responseMessage, code = handleDeleteOrgKey(keyName)

	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	DoJSONWrite(w, code, responseMessage)
}

func handleOrgAddOrUpdate(keyName string, r *http.Request) ([]byte, int) {
	success := true
	decoder := json.NewDecoder(r.Body)
	var responseMessage []byte
	var newSession SessionState
	err := decoder.Decode(&newSession)
	code := 200

	if err != nil {
		log.Error("Couldn't decode new session object: ", err)
		code = 400
		success = false
		responseMessage = createError("Request malformed")
	} else {
		// Update our session object (create it)

		spec := GetSpecForOrg(keyName)
		var thisSessionManager SessionHandler

		if spec == nil {
			log.Warning("Couldn't find org session store in active API list")
			if config.SupressDefaultOrgStore {
				responseMessage = createError("No such organisation found in Active API list")
				return responseMessage, 400
			} else {
				thisSessionManager = &DefaultOrgStore
			}
		} else {
			thisSessionManager = spec.OrgSessionManager
		}

		do_reset := r.FormValue("reset_quota")
		if do_reset == "1" {
			thisSessionManager.ResetQuota(keyName, newSession)
			newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
			rawKey := QuotaKeyPrefix + publicHash(keyName)

			// manage quotas seperately
			DefaultQuotaStore.RemoveSession(rawKey)
		}

		err := thisSessionManager.UpdateSession(keyName, newSession, 0)
		if err != nil {
			responseMessage = createError("Error writing to key store " + err.Error())
			return responseMessage, 400
		}

		log.WithFields(logrus.Fields{
			"key": keyName,
		}).Debug("New org key added or updated.")
		success = true
	}

	var action string
	if r.Method == "POST" {
		action = "added"
	} else {
		action = "modified"
	}

	if success {
		response := APIModifyKeySuccess{
			keyName,
			"ok",
			action}

		responseMessage, err = json.Marshal(&response)

		if err != nil {
			log.Error("Could not create response message: ", err)
			code = 500
			responseMessage = []byte(E_SYSTEM_ERROR)
		}
	}

	return responseMessage, code
}

func handleGetOrgDetail(ORGID string) ([]byte, int) {
	success := true
	var responseMessage []byte
	var err error
	code := 200

	thiSpec := GetSpecForOrg(ORGID)
	if thiSpec == nil {
		notFound := APIStatusMessage{"error", "Org not found"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 400
	}

	thisSession, ok := thiSpec.OrgSessionManager.GetSessionDetail(ORGID)
	if !ok {
		success = false
	} else {
		responseMessage, err = json.Marshal(&thisSession)
		if err != nil {
			log.Error("Marshalling failed: ", err)
			success = false
		}
	}

	if !success {
		notFound := APIStatusMessage{"error", "Org not found"}
		responseMessage, _ = json.Marshal(&notFound)
		code = 404
		log.WithFields(logrus.Fields{
			"Org": ORGID,
		}).Debug("Attempted key retrieval - failure.")
	} else {
		log.WithFields(logrus.Fields{
			"Org": ORGID,
		}).Debug("Attempted key retrieval - success.")
	}

	return responseMessage, code
}

func handleGetAllOrgKeys(filter, ORGID string) ([]byte, int) {
	success := true
	var responseMessage []byte
	code := 200

	var err error

	thiSpec := GetSpecForOrg(ORGID)
	if thiSpec == nil {
		notFound := APIStatusMessage{"error", "ORG not found"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 400
	}

	sessions := thiSpec.OrgSessionManager.GetSessions(filter)
	fixed_sessions := make([]string, 0)
	for _, s := range sessions {
		if !strings.Contains(s, QuotaKeyPrefix) {
			if !strings.Contains(s, RateLimitKeyPrefix) {
				fixed_sessions = append(fixed_sessions, s)
			}
		}
	}
	sessionsObj := APIAllKeys{fixed_sessions}

	responseMessage, err = json.Marshal(&sessionsObj)
	if err != nil {
		log.Error("Marshalling failed: ", err)
		success = false
		code = 500
	}

	if success {
		return responseMessage, code
	}

	log.Debug("Attempted orgs retrieval - success.")
	return []byte(E_SYSTEM_ERROR), code

}

func handleDeleteOrgKey(ORGID string) ([]byte, int) {
	var responseMessage []byte
	var err error

	thiSpec := GetSpecForOrg(ORGID)
	if thiSpec == nil {
		notFound := APIStatusMessage{"error", "Org not found"}
		responseMessage, _ = json.Marshal(&notFound)
		return responseMessage, 400
	}

	thiSpec.OrgSessionManager.RemoveSession(ORGID)
	code := 200

	statusObj := APIModifyKeySuccess{ORGID, "ok", "deleted"}
	responseMessage, err = json.Marshal(&statusObj)

	if err != nil {
		log.Error("Marshalling failed: ", err)
		return []byte(E_SYSTEM_ERROR), 500
	}

	log.WithFields(logrus.Fields{
		"key": ORGID,
	}).Debug("Attempted org key deletion - success.")

	return responseMessage, code
}

func groupResetHandler(w http.ResponseWriter, r *http.Request) {
	var responseMessage []byte
	var code int

	if r.Method == "GET" {
		log.Info("Group reload: sending to channel")
		responseMessage, code = signalGroupReload()

	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	DoJSONWrite(w, code, responseMessage)
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
	var responseMessage []byte
	var code int

	if r.Method == "GET" {
		responseMessage, code = handleURLReload()

	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	DoJSONWrite(w, code, responseMessage)
}

func expandKey(orgID, key string) string {
	if orgID == "" {
		return fmt.Sprintf("%s", key)
	}

	return fmt.Sprintf("%s%s", orgID, key)
}

func extractKey(orgID, key string) string {
	replacementStr := fmt.Sprintf("%s", orgID)
	replaced := strings.Replace(key, replacementStr, "", 1)
	return replaced
}

func createKeyHandler(w http.ResponseWriter, r *http.Request) {
	var responseMessage []byte
	code := 200
	var responseObj = APIModifyKeySuccess{}

	if r.Method == "POST" {
		decoder := json.NewDecoder(r.Body)
		var newSession SessionState
		err := decoder.Decode(&newSession)

		if err != nil {
			responseMessage = []byte(E_SYSTEM_ERROR)
			code = 500
			log.Error("Couldn't decode body: ", err)

		} else {

			newKey := keyGen.GenerateAuthKey(newSession.OrgID)
			if newSession.HMACEnabled {
				newSession.HmacSecret = keyGen.GenerateHMACSecret()
			}

			if len(newSession.AccessRights) > 0 {
				for apiId, _ := range newSession.AccessRights {
					thisAPISpec := GetSpecForApi(apiId)
					if thisAPISpec != nil {
						checkAndApplyTrialPeriod(newKey, apiId, &newSession)
						// If we have enabled HMAC checking for keys, we need to generate a secret for the client to use
						if !thisAPISpec.DontSetQuotasOnCreate {
							// Reset quota by default
							thisAPISpec.SessionManager.ResetQuota(newKey, newSession)
							newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
						}
						err := thisAPISpec.SessionManager.UpdateSession(newKey, newSession, thisAPISpec.SessionLifetime)
						if err != nil {
							responseMessage = createError("Failed to create key - " + err.Error())
							DoJSONWrite(w, 403, responseMessage)
							return
						}
					} else {
						log.WithFields(logrus.Fields{
							"apiID": apiId,
						}).Error("Could not create key for this API ID, API doesn't exist.")
						responseMessage = createError("Could not create key for this API ID, API doesn't exist.")
						DoJSONWrite(w, 403, responseMessage)
						return
					}
				}
			} else {
				if config.AllowMasterKeys {
					// nothing defined, add key to ALL
					log.Warning("No API Access Rights set, adding key to ALL.")
					for _, spec := range ApiSpecRegister {
						checkAndApplyTrialPeriod(newKey, spec.APIID, &newSession)
						if !spec.DontSetQuotasOnCreate {
							// Reset quote by default
							spec.SessionManager.ResetQuota(newKey, newSession)
							newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
						}
						err := spec.SessionManager.UpdateSession(newKey, newSession, spec.SessionLifetime)
						if err != nil {
							responseMessage = createError("Failed to create key - " + err.Error())
							DoJSONWrite(w, 403, responseMessage)
							return
						}
					}
				} else {
					log.Error("Master keys disallowed in configuration, key not added.")
					responseMessage = createError("Failed to create key, keys must have at least one Access Rights record set.")
					code = 403
					DoJSONWrite(w, code, responseMessage)
					return
				}

			}

			responseObj.Action = "create"
			responseObj.Key = newKey
			responseObj.Status = "ok"

			responseMessage, err = json.Marshal(&responseObj)

			if err != nil {
				log.Error("Marshalling failed: ", err)
				responseMessage = []byte(E_SYSTEM_ERROR)
				code = 500
			} else {
				log.WithFields(logrus.Fields{
					"key": newKey,
				}).Debug("Generated new key - success.")
			}
		}

	} else {
		code = 405
		responseMessage = createError("Method not supported")
	}

	DoJSONWrite(w, code, responseMessage)
}

// NewClientRequest is an outward facing JSON object translated from osin OAuthClients
type NewClientRequest struct {
	ClientRedirectURI string `json:"redirect_uri"`
	APIID             string `json:"api_id"`
}

func createOauthClientStorageID(APIID string, clientID string) string {
	// storageID := OAUTH_PREFIX + APIID + "." + CLIENT_PREFIX + clientID
	storageID := CLIENT_PREFIX + clientID
	return storageID
}

func createOauthClient(w http.ResponseWriter, r *http.Request) {
	var responseMessage []byte
	code := 200

	if r.Method == "POST" {
		decoder := json.NewDecoder(r.Body)
		var newOauthClient NewClientRequest
		err := decoder.Decode(&newOauthClient)

		if err != nil {
			responseMessage = []byte(E_SYSTEM_ERROR)
			code = 500
			log.Error("Couldn't decode body: ", err)

		}

		u5, err := uuid.NewV4()
		cleanSting := strings.Replace(u5.String(), "-", "", -1)
		u5Secret, err := uuid.NewV4()
		secret := base64.StdEncoding.EncodeToString([]byte(u5Secret.String()))

		newClient := osin.DefaultClient{
			Id:          cleanSting,
			RedirectUri: newOauthClient.ClientRedirectURI,
			Secret:      secret,
		}

		storageID := createOauthClientStorageID(newOauthClient.APIID, newClient.GetId())
		log.Debug("Storage ID: ", storageID)

		thisAPISpec := GetSpecForApi(newOauthClient.APIID)
		if thisAPISpec == nil {
			log.WithFields(logrus.Fields{
				"apiID": newOauthClient.APIID,
			}).Error("Could not create key for this API ID, API doesn't exist.")
		}

		storeErr := thisAPISpec.OAuthManager.OsinServer.Storage.SetClient(storageID, &newClient, true)

		if storeErr != nil {
			log.Error("Failed to save new client data: ", storeErr)
			responseMessage = createError("Failure in storing client data.")
		}

		reportableClientData := OAuthClient{
			ClientID:          newClient.GetId(),
			ClientSecret:      newClient.GetSecret(),
			ClientRedirectURI: newClient.GetRedirectUri(),
		}

		responseMessage, err = json.Marshal(&reportableClientData)

		if err != nil {
			log.Error("Marshalling failed: ", err)
			responseMessage = []byte(E_SYSTEM_ERROR)
			code = 500
		} else {
			log.WithFields(logrus.Fields{
				"key": newClient.GetId(),
			}).Debug("New OAuth Client registered successfully.")
		}

	} else {
		code = 405
		responseMessage = createError("Method not supported")
	}

	DoJSONWrite(w, code, responseMessage)
}

func invalidateOauthRefresh(w http.ResponseWriter, r *http.Request) {
	keyCombined := r.URL.Path[len("/tyk/oauth/refresh/"):]

	if r.Method == "DELETE" {
		APIID := r.FormValue("api_id")
		if APIID == "" {
			DoJSONWrite(w, 400, createError("Missing parameter api_id"))
			return
		}
		thisAPISpec := GetSpecForApi(APIID)
		log.Warning("Looking for refresh token in API ID: ", APIID)
		if thisAPISpec == nil {
			DoJSONWrite(w, 400, createError("API for this refresh token not found"))
			return
		}

		if thisAPISpec.OAuthManager == nil {
			DoJSONWrite(w, 400, createError("OAuth is not enabled on this API"))
			return
		}

		storeErr := thisAPISpec.OAuthManager.OsinServer.Storage.RemoveRefresh(keyCombined)

		if storeErr != nil {
			log.Error("Failed to invalidate refresh token: ", storeErr)
			DoJSONWrite(w, 400, createError("Failed to invalidate refresh token"))
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
			DoJSONWrite(w, 400, createError("Failed to marshal data"))
			return
		}

		DoJSONWrite(w, 200, responseMessage)
		return
	}

	DoJSONWrite(w, 405, createError("Method not supported"))
	return

}

func oAuthClientHandler(w http.ResponseWriter, r *http.Request) {
	keyCombined := r.URL.Path[len("/tyk/oauth/clients/"):]
	var responseMessage []byte
	var code int

	keyName := ""
	apiID := ""

	parts := strings.Split(keyCombined, "/")
	if len(parts) == 2 {
		keyName = parts[1]
		apiID = parts[0]
	} else if len(parts) == 1 {
		apiID = parts[0]
	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
		DoJSONWrite(w, code, responseMessage)
		return
	}

	if r.Method == "GET" {
		if keyName != "" {
			// Return single client detail
			responseMessage, code = getOauthClientDetails(keyName, apiID)
		} else {
			// Return list of keys
			responseMessage, code = getOauthClients(apiID)
		}

	} else if r.Method == "DELETE" {
		// Remove a key
		responseMessage, code = handleDeleteOAuthClient(keyName, apiID)

	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	DoJSONWrite(w, code, responseMessage)
}

// Get client details
func getOauthClientDetails(keyName string, APIID string) ([]byte, int) {
	success := true
	var responseMessage []byte
	var err error
	code := 200

	storageID := createOauthClientStorageID(APIID, keyName)
	thisAPISpec := GetSpecForApi(APIID)
	if thisAPISpec == nil {
		log.WithFields(logrus.Fields{
			"apiID": APIID,
		}).Error("Could ot get Client Details, API doesn't exist.")
		notFound := APIStatusMessage{"error", "OAuth Client ID not found"}
		responseMessage, _ = json.Marshal(&notFound)
		code = 404
		return responseMessage, code
	}

	thisClientData, getClientErr := thisAPISpec.OAuthManager.OsinServer.Storage.GetClientNoPrefix(storageID)
	if getClientErr != nil {
		success = false
	} else {
		reportableClientData := OAuthClient{
			ClientID:          thisClientData.GetId(),
			ClientSecret:      thisClientData.GetSecret(),
			ClientRedirectURI: thisClientData.GetRedirectUri(),
		}
		responseMessage, err = json.Marshal(&reportableClientData)
		if err != nil {
			log.Error("Marshalling failed: ", err)
			success = false
		}
	}

	if !success {
		notFound := APIStatusMessage{"error", "OAuth Client ID not found"}
		responseMessage, _ = json.Marshal(&notFound)
		code = 404
		log.WithFields(logrus.Fields{
			"key": keyName,
		}).Warning("Attempted oauth client retrieval - failure.")
	} else {
		log.WithFields(logrus.Fields{
			"key": keyName,
		}).Debug("Attempted oauth client retrieval - success.")
	}

	return responseMessage, code
}

// Delete Client
func handleDeleteOAuthClient(keyName string, APIID string) ([]byte, int) {
	var responseMessage []byte
	var err error

	storageID := createOauthClientStorageID(APIID, keyName)

	thisAPISpec := GetSpecForApi(APIID)
	if thisAPISpec == nil {
		log.WithFields(logrus.Fields{
			"apiID": APIID,
		}).Error("Could ot get Client Details, API doesn't exist.")
		notFound := APIStatusMessage{"error", "OAuth Client ID not found"}
		responseMessage, _ = json.Marshal(&notFound)

		return responseMessage, 400
	}

	osinErr := thisAPISpec.OAuthManager.OsinServer.Storage.DeleteClient(storageID, true)

	code := 200
	statusObj := APIModifyKeySuccess{keyName, "ok", "deleted"}

	if osinErr != nil {
		code = 500
		errObj := APIErrorMessage{"error", "Delete failed"}
		responseMessage, err = json.Marshal(&errObj)
		return responseMessage, code
	}

	responseMessage, err = json.Marshal(&statusObj)

	if err != nil {
		log.Error("Marshalling failed: ", err)
		return []byte(E_SYSTEM_ERROR), 500
	}

	log.WithFields(logrus.Fields{
		"key": keyName,
	}).Debug("Attempted OAuth client deletion - success.")

	return responseMessage, code
}

// List Clients
func getOauthClients(APIID string) ([]byte, int) {
	success := true
	var responseMessage []byte
	var err error
	code := 200

	// filterID := OAUTH_PREFIX + APIID + "." + CLIENT_PREFIX
	filterID := CLIENT_PREFIX
	log.Debug("Filtering by: ", filterID)
	thisAPISpec := GetSpecForApi(APIID)
	if thisAPISpec == nil {
		log.WithFields(logrus.Fields{
			"apiID": APIID,
		}).Error("Could ot get Client Details, API doesn't exist.")
		notFound := APIStatusMessage{"error", "OAuth Client ID not found"}
		responseMessage, _ = json.Marshal(&notFound)

		return responseMessage, 400
	}

	thisClientData, getClientsErr := thisAPISpec.OAuthManager.OsinServer.Storage.GetClients(filterID, true)
	if getClientsErr != nil {
		success = false
	} else {
		clients := []OAuthClient{}
		for _, osinClient := range thisClientData {
			reportableClientData := OAuthClient{
				ClientID:          osinClient.GetId(),
				ClientSecret:      osinClient.GetSecret(),
				ClientRedirectURI: osinClient.GetRedirectUri(),
			}
			clients = append(clients, reportableClientData)
		}

		responseMessage, err = json.Marshal(&clients)
		if err != nil {
			log.Error("Marshalling failed: ", err)
			success = false
		}
	}

	if !success {
		notFound := APIStatusMessage{"error", "OAuth slients not found"}
		responseMessage, _ = json.Marshal(&notFound)
		code = 404
		log.WithFields(logrus.Fields{
			"API": APIID,
		}).Warning("Attempted oauth client retrieval - failure.")
	} else {
		log.WithFields(logrus.Fields{
			"API": APIID,
		}).Debug("Attempted oauth clients retrieval - success.")
	}

	return responseMessage, code
}

func healthCheckhandler(w http.ResponseWriter, r *http.Request) {
	var responseMessage []byte
	var code int = 200

	if r.Method == "GET" {
		if config.HealthCheck.EnableHealthChecks {
			APIID := r.FormValue("api_id")
			if APIID == "" {
				code = 405
				responseMessage = createError("missing api_id parameter")
			} else {
				thisAPISpec := GetSpecForApi(APIID)
				if thisAPISpec != nil {
					health, _ := thisAPISpec.Health.GetApiHealthValues()
					var jsonErr error
					responseMessage, jsonErr = json.Marshal(health)
					if jsonErr != nil {
						code = 405
						responseMessage = createError("Failed to encode data")
					}
				} else {
					code = 405
					responseMessage = createError("API ID not found")
				}

			}
		} else {
			code = 405
			responseMessage = createError("Health checks are not enabled for this node")
		}
	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	DoJSONWrite(w, code, responseMessage)
}

func UserRatesCheck() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		code := 200

		thisSessionState := context.Get(r, SessionData)
		if thisSessionState == nil {
			code = 405
			responseMessage := createError("Health checks are not enabled for this node")
			DoJSONWrite(w, code, responseMessage)
			return
		}

		userSession := thisSessionState.(SessionState)
		returnSession := PublicSessionState{}
		returnSession.Quota.QuotaRenews = userSession.QuotaRenews
		returnSession.Quota.QuotaRemaining = userSession.QuotaRemaining
		returnSession.Quota.QuotaMax = userSession.QuotaMax
		returnSession.RateLimit.Rate = userSession.Rate
		returnSession.RateLimit.Per = userSession.Per

		responseMessage, jsonErr := json.Marshal(returnSession)
		if jsonErr != nil {
			code = 405
			responseMessage = createError("Failed to encode data")
			DoJSONWrite(w, code, responseMessage)
			return
		}

		DoJSONWrite(w, code, responseMessage)

		return
	}
}
