package certcheck

import (
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/model"
)

// FireEventFunc is a function that fires an event.
type FireEventFunc func(name apidef.TykEvent, meta interface{})

// APIMetaData is a structure that holds information about an API.
type APIMetaData struct {
	APIID   string
	APIName string
}

// CertInfo is a structure that holds information about a certificate.
type CertInfo struct {
	ID               string
	CommonName       string
	NotAfter         time.Time
	HoursUntilExpiry int
}

// EventCertificateExpiringSoonMeta is the metadata structure for certificate expiration events.
type EventCertificateExpiringSoonMeta struct {
	model.EventMetaDefault
	CertID        string    `json:"cert_id"`
	CertName      string    `json:"cert_name"`
	ExpiresAt     time.Time `json:"expires_at"`
	DaysRemaining int       `json:"days_remaining"`
}

// EventCertificateExpiredMeta is the metadata structure for certificate expiration events.
type EventCertificateExpiredMeta struct {
	model.EventMetaDefault
	CertID          string    `json:"cert_id"`
	CertName        string    `json:"cert_name"`
	ExpiredAt       time.Time `json:"expired_at"`
	DaysSinceExpiry int       `json:"days_since_expiry"`
}
