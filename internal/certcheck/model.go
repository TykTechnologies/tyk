package certcheck

import (
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/model"
)

type FireEventFunc func(name apidef.TykEvent, meta interface{})

type CertInfo struct {
	ID               string
	CommonName       string
	NotAfter         time.Time
	HoursUntilExpiry int
}

// EventCertificateExpiringSoonMeta is the metadata structure for certificate expiration events
type EventCertificateExpiringSoonMeta struct {
	model.EventMetaDefault
	CertID        string    `json:"cert_id"`
	CertName      string    `json:"cert_name"`
	ExpiresAt     time.Time `json:"expires_at"`
	DaysRemaining int       `json:"days_remaining"`
}

type EventCertificateExpiredMeta struct {
	model.EventMetaDefault
	CertID          string    `json:"cert_id"`
	CertName        string    `json:"cert_name"`
	ExpiredAt       time.Time `json:"expired_at"`
	DaysSinceExpiry int       `json:"days_since_expiry"`
}
