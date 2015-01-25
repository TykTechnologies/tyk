package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/RangelReale/osin"
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/lonelycode/tykcommon"
	"github.com/nu7hatch/gouuid"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
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
		log.Error("Couldn't marshal error stats")
		log.Error(err)
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

func doAddOrUpdate(keyName string, newSession SessionState, dontReset bool) {
	if len(newSession.AccessRights) > 0 {
		// We have a specific list of access rules, only add / update those
		for apiId, _ := range newSession.AccessRights {
			thisAPISpec := GetSpecForApi(apiId)
			if thisAPISpec != nil {
				// Lets reset keys if they are edited by admin
				thisAPISpec.SessionManager.UpdateSession(keyName, newSession, thisAPISpec.SessionLifetime)
				if !thisAPISpec.DontSetQuotasOnCreate {
					// Reset quote by default
					if !dontReset {
						thisAPISpec.SessionManager.ResetQuota(keyName, newSession)
					}
				}
			} else {
				log.WithFields(logrus.Fields{
					"key":   keyName,
					"apiID": apiId,
				}).Error("Could not add key for this API ID, API doesn't exist.")
			}
		}
	} else {
		// nothing defined, add key to ALL
		log.Warning("No API Access Rights set, adding key to ALL.")
		for _, spec := range ApiSpecRegister {
			spec.SessionManager.UpdateSession(keyName, newSession, spec.SessionLifetime)
		}
	}

	log.WithFields(logrus.Fields{
		"key": keyName,
	}).Info("New key added or updated.")
}

// ---- TODO: This changes the URL structure of the API completely ----
// ISSUE: If Session stores are stored with API specs, then managing keys will need to be done per store, i.e. add to all stores,
// remove from all stores, update to all stores, stores handle quotas separately though because they are localised! Keys will
// need to be managed by API, but only for GetDetail, GetList, UpdateKey and DeleteKey

func handleAddOrUpdate(keyName string, r *http.Request) ([]byte, int) {
	success := true
	decoder := json.NewDecoder(r.Body)
	var responseMessage []byte
	var newSession SessionState
	err := decoder.Decode(&newSession)
	code := 200

	if err != nil {
		log.Error("Couldn't decode new session object")
		log.Error(err)
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
			}

		}
		dont_reset := r.FormValue("suppress_reset")
		var suppress_reset bool = false

		if dont_reset == "1" {
			suppress_reset = true
		}
		doAddOrUpdate(keyName, newSession, suppress_reset)
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
			log.Error("Could not create response message")
			log.Error(err)
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
			log.Error("Marshalling failed")
			log.Error(err)
			success = false
		}
	}

	if !success {
		notFound := APIStatusMessage{"error", "Key not found"}
		responseMessage, _ = json.Marshal(&notFound)
		code = 404
		log.WithFields(logrus.Fields{
			"key": sessionKey,
		}).Info("Attempted key retrieval - failure.")
	} else {
		log.WithFields(logrus.Fields{
			"key": sessionKey,
		}).Info("Attempted key retrieval - success.")
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
    for _, s := range(sessions) {
        if !strings.Contains(s, QuotaKeyPrefix) {
            if !strings.Contains(s, RateLimitKeyPrefix) {
                fixed_sessions = append(fixed_sessions, s)
            }
        }
    }
    
	sessionsObj := APIAllKeys{fixed_sessions}

	responseMessage, err = json.Marshal(&sessionsObj)
	if err != nil {
		log.Error("Marshalling failed")
		log.Error(err)
		success = false
		code = 500
	}

	if success {
		return responseMessage, code
	}

	log.Info("Attempted keys retrieval - success.")
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
		}).Info("Attempted key deletion across all managed API's - success.")

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
		log.Error("Marshalling failed")
		log.Error(err)
		return []byte(E_SYSTEM_ERROR), 500
	}

	log.WithFields(logrus.Fields{
		"key": keyName,
	}).Info("Attempted key deletion - success.")

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
		log.Error("Marshalling failed")
		log.Error(err)
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
			log.Error("Could not create response message")
			log.Error(err)
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
			log.Error("Could not create response message")
			log.Error(err)
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

	log.Warning(r.Method)
	if r.Method == "GET" {
		if APIID != "" {
			log.Info("Requesting API definition for", APIID)
			responseMessage, code = HandleGetAPI(APIID)
		} else {
			log.Info("Requesting API list")
			responseMessage, code = HandleGetAPIList()
		}

	} else if r.Method == "POST" {
		log.Info("Creating new definition file")
		responseMessage, code = HandleAddOrUpdateApi(APIID, r)
	} else if r.Method == "PUT" {
		log.Info("Updating existing API: ", APIID)
		responseMessage, code = HandleAddOrUpdateApi(APIID, r)
	} else if r.Method == "DELETE" {
		log.Info("Deleting existing API: ", APIID)
		if APIID != "" {
			log.Info("Deleting API definition for: ", APIID)
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
		// Remove a key
		responseMessage, code = handleDeleteKey(keyName, APIID)

	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	DoJSONWrite(w, code, responseMessage)
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
		log.Error("Couldn't decode new session object")
		log.Error(err)
		code = 400
		success = false
		responseMessage = createError("Request malformed")
	} else {
		// Update our session object (create it)

		spec := GetSpecForOrg(keyName)
		if spec == nil {
			responseMessage = createError("No such organisation found in Active API list")
			return responseMessage, 400
		}

		spec.OrgSessionManager.UpdateSession(keyName, newSession, 0)

		do_reset := r.FormValue("reset_quota")
		if do_reset == "1" {
			spec.OrgSessionManager.ResetQuota(keyName, newSession)
		}

		log.WithFields(logrus.Fields{
			"key": keyName,
		}).Info("New org key added or updated.")
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
			log.Error("Could not create response message")
			log.Error(err)
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
			log.Error("Marshalling failed")
			log.Error(err)
			success = false
		}
	}

	if !success {
		notFound := APIStatusMessage{"error", "Org not found"}
		responseMessage, _ = json.Marshal(&notFound)
		code = 404
		log.WithFields(logrus.Fields{
			"Org": ORGID,
		}).Info("Attempted key retrieval - failure.")
	} else {
		log.WithFields(logrus.Fields{
			"Org": ORGID,
		}).Info("Attempted key retrieval - success.")
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
    for _, s := range(sessions) {
        if !strings.Contains(s, QuotaKeyPrefix) {
            if !strings.Contains(s, RateLimitKeyPrefix) {
                fixed_sessions = append(fixed_sessions, s)
            }
        }
    }
	sessionsObj := APIAllKeys{fixed_sessions}

	responseMessage, err = json.Marshal(&sessionsObj)
	if err != nil {
		log.Error("Marshalling failed")
		log.Error(err)
		success = false
		code = 500
	}

	if success {
		return responseMessage, code
	}

	log.Info("Attempted orgs retrieval - success.")
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
		log.Error("Marshalling failed")
		log.Error(err)
		return []byte(E_SYSTEM_ERROR), 500
	}

	log.WithFields(logrus.Fields{
		"key": ORGID,
	}).Info("Attempted org key deletion - success.")

	return responseMessage, code
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
			log.Error("Couldn't decode body")
			log.Error(err)

		} else {

			newKey := keyGen.GenerateAuthKey(newSession.OrgID)
			if newSession.HMACEnabled {
				newSession.HmacSecret = keyGen.GenerateHMACSecret()
			}

			if len(newSession.AccessRights) > 0 {
				for apiId, _ := range newSession.AccessRights {
					thisAPISpec := GetSpecForApi(apiId)
					if thisAPISpec != nil {
						// If we have enabled HMAC checking for keys, we need to generate a secret for the client to use
						thisAPISpec.SessionManager.UpdateSession(newKey, newSession, thisAPISpec.SessionLifetime)
						if !thisAPISpec.DontSetQuotasOnCreate {
							// Reset quota by default
							thisAPISpec.SessionManager.ResetQuota(newKey, newSession)
						}
					} else {
						log.WithFields(logrus.Fields{
							"apiID": apiId,
						}).Error("Could not create key for this API ID, API doesn't exist.")
					}
				}
			} else {
				// nothing defined, add key to ALL
				log.Warning("No API Access Rights set, adding key to ALL.")
				for _, spec := range ApiSpecRegister {
					spec.SessionManager.UpdateSession(newKey, newSession, spec.SessionLifetime)
					if !spec.DontSetQuotasOnCreate {
						// Reset quote by default
						spec.SessionManager.ResetQuota(newKey, newSession)
					}
				}
			}

			responseObj.Action = "create"
			responseObj.Key = newKey
			responseObj.Status = "ok"

			responseMessage, err = json.Marshal(&responseObj)

			if err != nil {
				log.Error("Marshalling failed")
				log.Error(err)
				responseMessage = []byte(E_SYSTEM_ERROR)
				code = 500
			} else {
				log.WithFields(logrus.Fields{
					"key": newKey,
				}).Info("Generated new key - success.")
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
	storageID := OAUTH_PREFIX + APIID + "." + CLIENT_PREFIX + clientID
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
			log.Error("Couldn't decode body")
			log.Error(err)

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
			log.Error("Marshalling failed")
			log.Error(err)
			responseMessage = []byte(E_SYSTEM_ERROR)
			code = 500
		} else {
			log.WithFields(logrus.Fields{
				"key": newClient.GetId(),
			}).Info("New OAuth Client registered successfully.")
		}

	} else {
		code = 405
		responseMessage = createError("Method not supported")
	}

	DoJSONWrite(w, code, responseMessage)
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
			log.Error("Marshalling failed")
			log.Error(err)
			success = false
		}
	}

	if !success {
		notFound := APIStatusMessage{"error", "OAuth Client ID not found"}
		responseMessage, _ = json.Marshal(&notFound)
		code = 404
		log.WithFields(logrus.Fields{
			"key": keyName,
		}).Info("Attempted oauth client retrieval - failure.")
	} else {
		log.WithFields(logrus.Fields{
			"key": keyName,
		}).Info("Attempted oauth client retrieval - success.")
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
		log.Error("Marshalling failed")
		log.Error(err)
		return []byte(E_SYSTEM_ERROR), 500
	}

	log.WithFields(logrus.Fields{
		"key": keyName,
	}).Info("Attempted OAuth client deletion - success.")

	return responseMessage, code
}

// List Clients
func getOauthClients(APIID string) ([]byte, int) {
	success := true
	var responseMessage []byte
	var err error
	code := 200

	filterID := OAUTH_PREFIX + APIID + "." + CLIENT_PREFIX

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
			log.Error("Marshalling failed")
			log.Error(err)
			success = false
		}
	}

	if !success {
		notFound := APIStatusMessage{"error", "OAuth slients not found"}
		responseMessage, _ = json.Marshal(&notFound)
		code = 404
		log.WithFields(logrus.Fields{
			"API": APIID,
		}).Info("Attempted oauth client retrieval - failure.")
	} else {
		log.WithFields(logrus.Fields{
			"API": APIID,
		}).Info("Attempted oauth clients retrieval - success.")
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
