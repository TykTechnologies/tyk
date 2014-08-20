package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/RangelReale/osin"
	"github.com/Sirupsen/logrus"
	"github.com/nu7hatch/gouuid"
	"net/http"
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

func GetSpecForApi(apiID string) *APISpec {
	spec, ok := ApiSpecRegister[apiId]
	if !ok {
		return nil
	}

	return spec
}

// TODO: This changes the URL structure of the API completely
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
		// Update our session object (create it)
		if newSession.BasicAuthData.Password != "" {
			// If we are using a basic auth user, then we need to make the keyname explicit against the OrgId in order to differentiate it
			// Only if it's NEW
			if r.Method == "POST" {
				keyName = newSession.OrgID + keyName
			}

		}

		for apiId, _ := range(newSession.AccessRights) {
			thisAPISpec := GetSpecForApi(apiId)
			if thisAPISpec != nil {
				thisAPISpec.SessionManager.UpdateSession(keyName, newSession)
			} else {
				log.WithFields(logrus.Fields{
					"key": keyName,
					"apiID": apiId,
				}).Error("Could not add key for this API ID, API doesn't exist.")
			}
		}

		log.WithFields(logrus.Fields{
			"key": keyName,
		}).Info("New key added or updated.")
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

func handleGetAllKeys(filter string) ([]byte, int) {
	success := true
	var responseMessage []byte
	code := 200

	var err error

	sessions := authManager.GetSessions(filter)
	sessionsObj := APIAllKeys{sessions}

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

func keyHandler(w http.ResponseWriter, r *http.Request) {
	keyName := r.URL.Path[len("/tyk/keys/"):]
	filter := r.FormValue("filter")
	var responseMessage []byte
	var code int

	if r.Method == "POST" || r.Method == "PUT" {
		responseMessage, code = handleAddOrUpdate(keyName, r)

	} else if r.Method == "GET" {
		if keyName != "" {
			// Return single key detail
			responseMessage, code = handleGetDetail(keyName)
		} else {
			// Return list of keys
			responseMessage, code = handleGetAllKeys(filter)
		}

	} else if r.Method == "DELETE" {
		// Remove a key
		responseMessage, code = handleDeleteKey(keyName)

	} else {
		// Return Not supported message (and code)
		code = 405
		responseMessage = createError("Method not supported")
	}

	w.WriteHeader(code)
	fmt.Fprintf(w, string(responseMessage))
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

	w.WriteHeader(code)
	fmt.Fprintf(w, string(responseMessage))
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
			newKey := authManager.GenerateAuthKey(newSession.OrgID)

			// If we have enabled HMAC checking for keys, we need to generate a secret for the client to use
			if newSession.HMACEnabled {
				newSession.HmacSecret = authManager.GenerateHMACSecret()
			}



			authManager.UpdateSession(newKey, newSession)
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

	w.WriteHeader(code)
	fmt.Fprintf(w, string(responseMessage))
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
		storeErr := genericOsinStorage.SetClient(storageID, &newClient, true)

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

	w.WriteHeader(code)
	fmt.Fprintf(w, string(responseMessage))
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
		w.WriteHeader(code)
		fmt.Fprintf(w, string(responseMessage))
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

	w.WriteHeader(code)
	fmt.Fprintf(w, string(responseMessage))
}

// Get client details
func getOauthClientDetails(keyName string, APIID string) ([]byte, int) {
	success := true
	var responseMessage []byte
	var err error
	code := 200

	storageID := createOauthClientStorageID(APIID, keyName)
	thisClientData, getClientErr := genericOsinStorage.GetClientNoPrefix(storageID)
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
	osinErr := genericOsinStorage.DeleteClient(storageID, true)

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
	thisClientData, getClientsErr := genericOsinStorage.GetClients(filterID, true)
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

// MakeNewOsinServer creates a generic osinStorage object, used primarily by the API to create and get keys outside of an APISpec context.
// This is not ideal, but is only used in the Tyk API and nowhere else.
func MakeNewOsinServer() *RedisOsinStorageInterface {
	log.Info("Creating generic redis OAuth connection")
	storageManager := RedisStorageManager{KeyPrefix: ""}
	storageManager.Connect()
	osinStorage := &RedisOsinStorageInterface{&storageManager}

	return osinStorage
}
