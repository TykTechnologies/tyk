package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

func registerOrgHandlers(r *mux.Router) {
	const (
		orgKeys        = "/org/keys"
		orgKeysKeyName = orgKeys + "/{keyName:[^/]*}"
	)

	r.StrictSlash(false)
	r.HandleFunc(orgKeys, orgListHandler).Methods(http.MethodGet)
	r.HandleFunc(orgKeysKeyName, orgShowHandler).Methods(http.MethodGet)
	r.HandleFunc(orgKeysKeyName, orgStoreUpdateHandler).Methods(http.MethodPut, http.MethodPost)
	r.HandleFunc(orgKeysKeyName, orgDeleteHandler).Methods(http.MethodDelete)
}

func orgListHandler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	obj, code := handleGetAllOrgKeys(filter)
	doJSONWrite(w, code, obj)
}

func orgShowHandler(w http.ResponseWriter, r *http.Request) {
	keyName := mux.Vars(r)["keyName"]

	obj, code := handleGetOrgDetail(keyName)
	doJSONWrite(w, code, obj)
}

func orgStoreUpdateHandler(w http.ResponseWriter, r *http.Request) {
	keyName := mux.Vars(r)["keyName"]

	obj, code := handleOrgAddOrUpdate(keyName, r)
	doJSONWrite(w, code, obj)
}

func orgDeleteHandler(w http.ResponseWriter, r *http.Request) {
	keyName := mux.Vars(r)["keyName"]

	obj, code := handleDeleteOrgKey(keyName)
	doJSONWrite(w, code, obj)
}

func handleGetAllOrgKeys(filter string) (interface{}, int) {
	spec := getSpecForOrg("")
	if spec == nil {
		return apiError("ORG not found"), http.StatusNotFound
	}

	sessions := spec.OrgSessionManager.Sessions(filter)
	fixed_sessions := make([]string, 0)
	for _, s := range sessions {
		if !strings.HasPrefix(s, QuotaKeyPrefix) && !strings.HasPrefix(s, RateLimitKeyPrefix) {
			fixed_sessions = append(fixed_sessions, s)
		}
	}
	sessionsObj := apiAllKeys{fixed_sessions}
	return sessionsObj, http.StatusOK
}

func handleGetOrgDetail(orgID string) (interface{}, int) {
	spec := getSpecForOrg(orgID)
	if spec == nil {
		return apiError("Org not found"), http.StatusNotFound
	}

	session, ok := spec.OrgSessionManager.SessionDetail(orgID, false)
	if !ok {
		log.WithFields(logrus.Fields{
			"prefix": "api",
			"org":    orgID,
			"status": "fail",
			"err":    "not found",
		}).Error("Failed retrieval of record for ORG ID.")
		return apiError("Org not found"), http.StatusNotFound
	}
	log.WithFields(logrus.Fields{
		"prefix": "api",
		"org":    orgID,
		"status": "ok",
	}).Info("Retrieved record for ORG ID.")
	return session, http.StatusOK
}

func handleOrgAddOrUpdate(keyName string, r *http.Request) (interface{}, int) {
	newSession := new(user.SessionState)

	if err := json.NewDecoder(r.Body).Decode(newSession); err != nil {
		log.Error("Couldn't decode new session object: ", err)
		return apiError("Request malformed"), http.StatusBadRequest
	}
	// Update our session object (create it)

	spec := getSpecForOrg(keyName)
	var sessionManager SessionHandler

	if spec == nil {
		log.Warning("Couldn't find org session store in active API list")
		if config.Global().SupressDefaultOrgStore {
			return apiError("No such organisation found in Active API list"), http.StatusNotFound
		}
		sessionManager = &DefaultOrgStore
	} else {
		sessionManager = spec.OrgSessionManager
	}

	if r.URL.Query().Get("reset_quota") == "1" {
		sessionManager.ResetQuota(keyName, newSession, false)
		newSession.QuotaRenews = time.Now().Unix() + newSession.QuotaRenewalRate
		rawKey := QuotaKeyPrefix + storage.HashKey(keyName)

		// manage quotas separately
		DefaultQuotaStore.RemoveSession(rawKey, false)
	}

	err := sessionManager.UpdateSession(keyName, newSession, 0, false)
	if err != nil {
		return apiError("Error writing to key store " + err.Error()), http.StatusInternalServerError
	}

	// identify that spec has org session
	if spec != nil {
		spec.Lock()
		spec.OrgHasNoSession = false
		spec.Unlock()
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

	return response, http.StatusOK
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

		return apiError("Org not found"), http.StatusNotFound
	}

	if !spec.OrgSessionManager.RemoveSession(orgID, false) {
		return apiError("Failed to remove the key"), http.StatusBadRequest
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"key":    orgID,
		"status": "ok",
	}).Info("Org key deleted.")

	// identify that spec has no org session
	// TODO: I think at this stage, condition is always true. Remove if?
	if spec != nil {
		spec.Lock()
		spec.OrgHasNoSession = true
		spec.Unlock()
	}

	statusObj := apiModifyKeySuccess{
		Key:    orgID,
		Status: "ok",
		Action: "deleted",
	}
	return statusObj, http.StatusOK
}
