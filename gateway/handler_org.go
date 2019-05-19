package gateway

import (
	"net/http"

	"github.com/gorilla/mux"
)

type HandlerOrg struct{}

func (h HandlerOrg) RegisterRoutes(r *mux.Router) {
	const (
		orgKeys        = "/org/keys"
		orgKeysKeyName = orgKeys + "/{keyName:[^/]*}"
	)

	r.StrictSlash(false)
	r.HandleFunc(orgKeys, h.Index).Methods(http.MethodGet)
	r.HandleFunc(orgKeysKeyName, h.Show).Methods(http.MethodGet)
	r.HandleFunc(orgKeysKeyName, h.Update).Methods(http.MethodPut)
	r.HandleFunc(orgKeysKeyName, h.Store).Methods(http.MethodPost)
	r.HandleFunc(orgKeysKeyName, h.Delete).Methods(http.MethodDelete)
}

func (h HandlerOrg) Index(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	obj, code := handleGetAllOrgKeys(filter)
	doJSONWrite(w, code, obj)
}

func (h HandlerOrg) Show(w http.ResponseWriter, r *http.Request) {
	keyName := mux.Vars(r)["keyName"]

	obj, code := handleGetOrgDetail(keyName)
	doJSONWrite(w, code, obj)
}

func (h HandlerOrg) Update(w http.ResponseWriter, r *http.Request) {
	keyName := mux.Vars(r)["keyName"]

	obj, code := handleOrgAddOrUpdate(keyName, r)
	doJSONWrite(w, code, obj)
}

func (h HandlerOrg) Store(w http.ResponseWriter, r *http.Request) {
	keyName := mux.Vars(r)["keyName"]

	obj, code := handleOrgAddOrUpdate(keyName, r)
	doJSONWrite(w, code, obj)
}

func (h HandlerOrg) Delete(w http.ResponseWriter, r *http.Request) {
	keyName := mux.Vars(r)["keyName"]

	obj, code := handleDeleteOrgKey(keyName)
	doJSONWrite(w, code, obj)
}
