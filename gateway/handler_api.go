package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	jsonpatch "gopkg.in/evanphx/json-patch.v4"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

func registerApiHandlers(r *mux.Router) {
	r.HandleFunc("/apis", apiListHandler).Methods(http.MethodGet)
	r.HandleFunc("/apis", apiStoreHandler).Methods(http.MethodPost)
	r.HandleFunc("/apis/{apiId}", apiShowHandler).Methods(http.MethodGet)
	r.HandleFunc("/apis/{apiId}", apiUpdateHandler).Methods(http.MethodPut)
	r.HandleFunc("/apis/{apiId}", apiPatchHandler).Methods(http.MethodPatch)
	r.HandleFunc("/apis/{apiID}", apiDeleteHandler).Methods(http.MethodDelete)

	r.HandleFunc("/apis/{apiID}/cache", apiDeleteCacheHandler).Methods(http.MethodDelete)
	r.HandleFunc("/apis/{apiID}/health", apiHealthHandler).Methods(http.MethodGet)

	// backwards compatibility endpoints
	r.HandleFunc("/cache/{apiID}", apiDeleteCacheHandler).Methods(http.MethodDelete)
	r.HandleFunc("/health", apiHealthHandler).Methods(http.MethodGet)
}

func apiListHandler(w http.ResponseWriter, _ *http.Request) {
	obj, code := handleGetAPIList()
	doJSONWrite(w, code, obj)
}

func apiShowHandler(w http.ResponseWriter, r *http.Request) {
	apiId := mux.Vars(r)["apiID"]
	obj, code := handleGetAPI(apiId)
	doJSONWrite(w, code, obj)
}

func apiStoreHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	obj, code := handleAddOrUpdateApi(apiID, r)

	doJSONWrite(w, code, obj)
}

func apiUpdateHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	obj, code := handleAddOrUpdateApi(apiID, r)

	if code == http.StatusOK {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	doJSONWrite(w, code, obj)
}

func apiPatchHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]

	jsBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		doJSONWrite(w, http.StatusBadRequest, apiError("unable to read body"))
		return
	}

	obj, code := handlePatchAPI(apiID, jsBody)
	doJSONWrite(w, code, obj)
}

func apiDeleteHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	obj, code := handleDeleteAPI(apiID)

	doJSONWrite(w, code, obj)
}

func apiDeleteCacheHandler(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]

	if err := handleInvalidateCache(apiID); err != nil {
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

		doJSONWrite(w, http.StatusInternalServerError, apiError("Cache invalidation failed"))
		return
	}

	doJSONWrite(w, http.StatusOK, apiOk("cache invalidated"))
}

func apiHealthHandler(w http.ResponseWriter, r *http.Request) {
	if !config.Global().HealthCheck.EnableHealthChecks {
		doJSONWrite(w, http.StatusBadRequest, apiError("Health checks are not enabled for this node"))
		return
	}

	apiID := mux.Vars(r)["apiID"]
	if apiID == "" {
		// fallback to querystring
		apiID = r.URL.Query().Get("api_id")
	}
	if apiID == "" {
		doJSONWrite(w, http.StatusBadRequest, apiError("missing api_id parameter"))
		return
	}

	apiSpec := getApiSpec(apiID)
	if apiSpec == nil {
		doJSONWrite(w, http.StatusNotFound, apiError("API ID not found"))
		return
	}
	health, _ := apiSpec.Health.ApiHealthValues()
	doJSONWrite(w, http.StatusOK, health)
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
	return apiIDList, http.StatusOK
}

func handleGetAPI(apiID string) (interface{}, int) {
	if spec := getApiSpec(apiID); spec != nil {
		return spec.APIDefinition, http.StatusOK
	}

	log.WithFields(logrus.Fields{
		"prefix": "api",
		"apiID":  apiID,
	}).Error("API doesn't exist.")
	return apiError("API not found"), http.StatusNotFound
}

func handleAddOrUpdateApi(apiID string, r *http.Request) (interface{}, int) {
	if config.Global().UseDBAppConfigs {
		log.Error("Rejected new API Definition due to UseDBAppConfigs = true")
		return apiError("Due to enabled use_db_app_configs, please use the Dashboard API"), http.StatusInternalServerError
	}

	newDef := &apidef.APIDefinition{}
	if err := json.NewDecoder(r.Body).Decode(newDef); err != nil {
		log.Error("Couldn't decode new API Definition object: ", err)
		return apiError("Request malformed"), http.StatusBadRequest
	}

	if apiID != "" && newDef.APIID != apiID {
		log.Error("PUT operation on different APIIDs")
		return apiError("Request APIID does not match that in Definition! For Updtae operations these must match."), http.StatusBadRequest
	}

	// Create a filename
	defFilePath := filepath.Join(config.Global().AppPath, newDef.APIID+".json")

	// If it exists, delete it
	if _, err := os.Stat(defFilePath); err == nil {
		log.Warning("API Definition with this ID already exists, deleting file...")
		os.Remove(defFilePath)
	}

	// unmarshal the object into the file
	asByte, err := json.MarshalIndent(newDef, "", "  ")
	if err != nil {
		log.Error("Marshalling of API Definition failed: ", err)
		return apiError("Marshalling failed"), http.StatusInternalServerError
	}

	if err := ioutil.WriteFile(defFilePath, asByte, 0644); err != nil {
		log.Error("Failed to create file! - ", err)
		return apiError("File object creation failed, write error"), http.StatusInternalServerError
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

	return response, http.StatusOK
}

func handlePatchAPI(apiID string, data []byte) (interface{}, int) {
	if config.Global().UseDBAppConfigs {
		log.Error("Rejected new API Definition due to UseDBAppConfigs = true")
		return apiError("Due to enabled use_db_app_configs, please use the Dashboard API"), http.StatusBadRequest
	}

	spec := getApiSpec(apiID)
	if spec == nil {
		return "api does not exist", http.StatusNotFound
	}

	// unmarshal the object into the file
	apiDefBytes, err := json.Marshal(spec.APIDefinition)
	if err != nil {
		log.Error("Marshalling of API Definition failed: ", err)
		return apiError("Marshalling failed"), http.StatusInternalServerError
	}

	patch, err := jsonpatch.DecodePatch(data)
	if err != nil {
		return apiError(fmt.Sprintf("decodePatch failed: %v", err)), http.StatusBadRequest
	}

	modified, err := patch.Apply(apiDefBytes)
	if err != nil {
		return apiError(fmt.Sprintf("patchApply failed: %v", err)), http.StatusBadRequest
	}

	var dest apidef.APIDefinition
	if err := json.Unmarshal(modified, &dest); err != nil {
		return apiError("unable to re-encode to apidef"), http.StatusInternalServerError
	}

	if apiID != dest.APIID {
		log.Error("Patch operation on different APIIDs")
		return apiError("Request APIID does not match that in Definition! For Updtae operations these must match."), http.StatusBadRequest
	}

	// Create a filename
	defFilePath := filepath.Join(config.Global().AppPath, dest.APIID+".json")

	// If it exists, delete it
	if _, err := os.Stat(defFilePath); err == nil {
		log.Warning("API Definition with this ID already exists, deleting file...")
		os.Remove(defFilePath)
	}

	// unmarshal the object into the file
	asByte, err := json.MarshalIndent(dest, "", "  ")
	if err != nil {
		log.Error("Marshalling of API Definition failed: ", err)
		return apiError("Marshalling failed"), http.StatusInternalServerError
	}

	if err := ioutil.WriteFile(defFilePath, asByte, 0644); err != nil {
		log.Error("Failed to create file! - ", err)
		return apiError("File object creation failed, write error"), http.StatusInternalServerError
	}

	response := apiModifyKeySuccess{
		Key:    dest.APIID,
		Status: "ok",
		Action: "patch",
	}

	return response, http.StatusOK
}

func handleDeleteAPI(apiID string) (interface{}, int) {
	// Generate a filename
	defFilePath := filepath.Join(config.Global().AppPath, apiID+".json")

	// If it exists, delete it
	if _, err := os.Stat(defFilePath); err != nil {
		log.Warning("File does not exist! ", err)
		return apiError("Delete failed"), http.StatusInternalServerError
	}

	os.Remove(defFilePath)

	response := apiModifyKeySuccess{
		Key:    apiID,
		Status: "ok",
		Action: "deleted",
	}

	return response, http.StatusOK
}

func handleInvalidateCache(apiId string) error {
	const (
		cacheFormat        = "cache-%s"
		matchPatternFormat = cacheFormat + "*"
	)
	store := storage.RedisCluster{KeyPrefix: fmt.Sprintf(cacheFormat, apiId), IsCache: true}
	if ok := store.DeleteScanMatch(fmt.Sprintf(matchPatternFormat, apiId)); !ok {
		return errors.New("scan/delete failed")
	}
	return nil
}
