package gateway

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

const (
	oasSpecEndpoint = "/spec"
)

// addOASSpecEndpoint adds a /spec endpoint to OAS APIs that returns the OAS definition
// This endpoint bypasses all middleware, including authentication, rate limiting, etc.
func (gw *Gateway) addOASSpecEndpoint(spec *APISpec, router *mux.Router, logger *logrus.Entry) {
	// Only add the endpoint to OAS APIs
	if !spec.IsOAS {
		return
	}

	logger.Debug("Adding OAS spec endpoint for API: ", spec.APIID)

	// Create a direct handler for the /spec endpoint that completely bypasses middleware
	// This is registered directly with the router, so it's processed before any middleware chain
	router.HandleFunc(oasSpecEndpoint, func(w http.ResponseWriter, r *http.Request) {
		// Set content type header
		w.Header().Set("Content-Type", "application/json")

		// Marshal the OAS definition to JSON
		oasJSON, err := json.Marshal(spec.OAS)
		if err != nil {
			logger.WithError(err).Error("Error marshaling OAS spec to JSON")
			http.Error(w, "Error generating OAS spec", http.StatusInternalServerError)
			return
		}

		// Write the response
		w.WriteHeader(http.StatusOK)
		w.Write(oasJSON)
	}).Methods(http.MethodGet)
}
