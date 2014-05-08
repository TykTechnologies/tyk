package main

import (
	"encoding/json"
	"fmt"
	"github.com/nu7hatch/gouuid"
	"net/http"
)

type ApiModifyKeySuccess struct {
	Key    string `json:"key"`
	Status string `json:"status"`
	Action string `json:"action"`
}

type ApiStatusMsg struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

func createError(errorMsg string) []byte {
	errorObj := ApiStatusMsg{"error", errorMsg}
	responseMsg, err := json.Marshal(&errorObj)

	if err != nil {
		log.Error("Couldn't marshal error stats")
		log.Error(err)
	}

	return responseMsg
}

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
		authManager.UpdateSession(keyName, newSession)
	}

	var action string
	if r.Method == "POST" {
		action = "added"
	} else {
		action = "modified"
	}

	if success {
		response := ApiModifyKeySuccess{
			keyName,
			"ok",
			action}

		responseMessage, err = json.Marshal(&response)

		if err != nil {
			log.Error("Could not create response message")
			log.Error(err)
			code = 500
			responseMessage = []byte(systemError)
		}
	}

	return responseMessage, code
}

func handleGetDetail(sessionKey string) ([]byte, int) {
	success := true
	var responseMessage []byte
	var err error
	code := 200

	thisSession, ok := authManager.GetSessionDetail(sessionKey)
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
		notFound := APIStatusMessage{false, "Key not found"}
		responseMessage, _ = json.Marshal(&notFound)
		code = 404
	}
	return responseMessage, code
}

type APIAllKeys struct {
	ApiKeys []string `json:"keys"`
}

func handleGetAllKeys() ([]byte, int) {
	success := true
	var responseMessage []byte
	code := 200

	var err error

	sessions := authManager.GetSessions()
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
	} else {
		return []byte(systemError), code
	}
}

type APIStatusMessage struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}

func handleDeleteKey(keyName string) ([]byte, int) {
	var responseMessage []byte
	var err error
	authManager.Store.DeleteKey(keyName)
	code := 200

	statusObj := APIStatusMessage{true, ""}
	responseMessage, err = json.Marshal(&statusObj)

	if err != nil {
		log.Error("Marshalling failed")
		log.Error(err)
		return []byte(systemError), 500
	}

	return responseMessage, code
}

func keyHandler(w http.ResponseWriter, r *http.Request) {
	keyName := r.URL.Path[len("/tyk/keys/"):]
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
			responseMessage, code = handleGetAllKeys()
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

func createKeyHandler(w http.ResponseWriter, r *http.Request) {
	var responseMessage []byte
	code := 200
	var responseObj = ApiModifyKeySuccess{}

	if r.Method == "POST" {
		decoder := json.NewDecoder(r.Body)
		var newSession SessionState
		err := decoder.Decode(&newSession)

		if err != nil {
			responseMessage = []byte(systemError)
			code = 500
			log.Error("Couldn't decode body")
			log.Error(err)

		} else {
			u5, err := uuid.NewV4()
			log.Info(u5.String())

			if err != nil {
				code = 400
				log.Error("Couldn't decode body")
				log.Error(err)
				responseMessage = createError("Request malformed")

			} else {
				keyName := u5.String()
				authManager.UpdateSession(keyName, newSession)
				responseObj.Action = "create"
				responseObj.Key = keyName
				responseObj.Status = "ok"

				responseMessage, err = json.Marshal(&responseObj)

				if err != nil {
					log.Error("Marshalling failed")
					log.Error(err)
					responseMessage = []byte(systemError)
					code = 500
				}

			}
		}

	} else {
		code = 405
		responseMessage = createError("Method not supported")
	}

	w.WriteHeader(code)
	fmt.Fprintf(w, string(responseMessage))
}

func securityHandler(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		tykAuthKey := r.Header.Get("x-tyk-authorisation")
		if tykAuthKey != config.Secret {
			// Error
			handle_error(w, r, "Authorisation failed", 403)
		} else {
			handler(w, r)
		}
	}
}
