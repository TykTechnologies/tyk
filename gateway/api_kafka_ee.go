//go:build ee || dev
package gateway

import (
	"github.com/gorilla/mux"
	"github.com/TykTechnologies/tyk/ee/middleware/streams/kafka"
)

func registerKafkaAPI(r *mux.Router) {
	r.HandleFunc("/streams/kafka/offset/reset", kafka.KafkaOffsetResetHandler).Methods("POST")
	r.HandleFunc("/streams/kafka/offset/commit", kafka.KafkaOffsetResetHandler).Methods("POST")
}
