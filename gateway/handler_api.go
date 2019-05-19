package gateway

import (
	"net/http"

	"github.com/gorilla/mux"
)

type HandlerApi struct{}

// Lists all APIs
func (HandlerApi) Index(w http.ResponseWriter, r *http.Request) {
	obj, code := handleGetAPIList()
	doJSONWrite(w, code, obj)
}

// Shows a single API by it's ID
func (HandlerApi) Show(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	obj, code := handleGetAPI(apiID)
	doJSONWrite(w, code, obj)
}

// Creates an API
func (HandlerApi) Store(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	obj, code := handleAddOrUpdateApi(apiID, r)
	doJSONWrite(w, code, obj)
}

// Updates an API
func (HandlerApi) Update(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	obj, code := handleAddOrUpdateApi(apiID, r)
	doJSONWrite(w, code, obj)
}

// Updates part of an API
func (HandlerApi) Patch(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}

// Deletes an API
func (HandlerApi) Delete(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	obj, code := handleDeleteAPI(apiID)
	doJSONWrite(w, code, obj)
}
