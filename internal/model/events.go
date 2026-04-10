package model

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/event"
)

// EventMetaDefault is a standard embedded struct to be used with custom event metadata types, gives an interface for
// easily extending event metadata objects
type EventMetaDefault struct {
	Message            string
	OriginatingRequest string
}

// NewEventMetaDefault creates an instance of model.EventMetaDefault.
func NewEventMetaDefault(r *http.Request, message string) EventMetaDefault {
	return EventMetaDefault{
		Message:            message,
		OriginatingRequest: event.EncodeRequestToEvent(r),
	}
}
