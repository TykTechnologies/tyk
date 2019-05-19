package gateway

import (
	"io/ioutil"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/repository/cache"
)

type HandlerApi struct{}

func (h HandlerApi) RegisterRoutes(r *mux.Router) {
	r.StrictSlash(false)
	r.HandleFunc("/apis", h.Index).Methods(http.MethodGet)
	r.HandleFunc("/apis", h.Store).Methods(http.MethodPost)
	r.HandleFunc("/apis/{apiID}", h.Show).Methods(http.MethodGet)
	r.HandleFunc("/apis/{apiID}", h.Update).Methods(http.MethodPut)
	r.HandleFunc("/apis/{apiID}", h.Patch).Methods(http.MethodPatch)
	r.HandleFunc("/apis/{apiID}", h.Delete).Methods(http.MethodDelete)
	r.HandleFunc("/apis/{apiID}/cache", h.DeleteCache).Methods(http.MethodDelete)
	r.HandleFunc("/cache/{apiID}", h.DeleteCache).Methods(http.MethodDelete)
}

// Lists all APIs
func (h HandlerApi) Index(w http.ResponseWriter, r *http.Request) {
	obj, code := handleGetAPIList()
	doJSONWrite(w, code, obj)
}

// Shows a single API by it's ID
func (h HandlerApi) Show(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	obj, code := handleGetAPI(apiID)
	doJSONWrite(w, code, obj)
}

// Creates an API
func (h HandlerApi) Store(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	obj, code := handleAddOrUpdateApi(apiID, r)

	if code == http.StatusOK {
		code = http.StatusCreated
	}

	doJSONWrite(w, code, obj)
}

// Updates an API
func (h HandlerApi) Update(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	obj, code := handleAddOrUpdateApi(apiID, r)

	if code == http.StatusOK {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	doJSONWrite(w, code, obj)
}

// Updates part of an API
func (h HandlerApi) Patch(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]

	jsBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		doJSONWrite(w, http.StatusBadRequest, apiError("unable to read body"))
		return
	}

	obj, code := handlePatchAPI(apiID, jsBody)
	doJSONWrite(w, code, obj)
}

// Deletes an API
func (h HandlerApi) Delete(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	obj, code := handleDeleteAPI(apiID)

	if code == http.StatusOK {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	doJSONWrite(w, code, obj)
}

func (h HandlerApi) DeleteCache(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]

	if err := (cache.Cache{}).Invalidate(apiID); err != nil {
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
