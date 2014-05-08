package main

import(
	"fmt"
	"net/http"
	"encoding/json"
)

type ApiModifyKeySuccess struct {
	Key string 		`json:"key"`
	Status string	`json:"status"`
	Action string	`json:"action"`
}

func addKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyName := r.URL.Path[len("/tyk/key/"):]
	success := true

	if r.Method == "POST" || r.Method == "PUT" {
		decoder := json.NewDecoder(r.Body)
		var newSession SessionState
		err := decoder.Decode(&newSession)

		if err != nil {
			log.Error("Couldn't decode new session object")
			log.Error(err)
			success = false
		} else {
			// Update our session object (create it)
			authManager.UpdateSession(keyName, newSession)
		}

		var responseMessage []byte
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
				responseMessage = []byte(systemError)
			}
		}

		fmt.Fprintf(w, string(responseMessage))
	} else {
		fmt.Fprintf(w, string(systemError))
	}
}
