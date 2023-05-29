package gateway

import (
	. "github.com/TykTechnologies/tyk/gateway/model"
	"github.com/sirupsen/logrus"
)

// Logger provides a log context for services.
func (*Gateway) Logger() *logrus.Logger {
	return log
}

// Notify issues a notification.
func (gw *Gateway) Notify(i Notification) {
	gw.MainNotifier.Notify(i)
}
