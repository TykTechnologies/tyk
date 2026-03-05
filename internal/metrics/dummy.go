package metrics

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/interfaces"
)

type dummy struct {
}

func (d *dummy) DecorateNotifier(notifier interfaces.Notifier) interfaces.Notifier {
	return notifier
}

func (d *dummy) Handler() http.Handler {
	return http.HandlerFunc(http.NotFound)
}

func (d *dummy) IncrPubSubDisconnect() {}

var _ Metrics = new(dummy)
