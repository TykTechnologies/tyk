//go:build !ee && !dev
package gateway

import "github.com/gorilla/mux"

func registerKafkaAPI(r *mux.Router) {}
