package config_helper

import (
	"encoding/json"
	"net/http"
)

func (h *ConfigHelper) JsonHandler(rw http.ResponseWriter, r *http.Request) {
	if h.config == nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-type", "application/json")
	rw.WriteHeader(http.StatusOK)

	json.NewEncoder(rw).Encode(h.config)
}

func (h *ConfigHelper) EnvsHandler(rw http.ResponseWriter, r *http.Request) {
	if h.config == nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-type", "application/json")
	rw.WriteHeader(http.StatusOK)
	json.NewEncoder(rw).Encode(h.ParseEnvs())
}
