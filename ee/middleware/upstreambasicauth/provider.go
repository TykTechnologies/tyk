package upstreambasicauth

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// Provider implements upstream auth provider.
type Provider struct {
	// Logger is the logger to be used.
	Logger *logrus.Entry
	// HeaderName is the header name to be used to fill upstream auth with.
	HeaderName string
	// AuthValue is the value of auth header.
	AuthValue string
}

// Fill sets the request's HeaderName with AuthValue
func (u Provider) Fill(r *http.Request) {
	if r.Header.Get(u.HeaderName) != "" {
		u.Logger.WithFields(logrus.Fields{
			"header": u.HeaderName,
		}).Info("Authorization header conflict detected: Client header overwritten by Gateway upstream authentication header.")
	}
	r.Header.Set(u.HeaderName, u.AuthValue)
}
