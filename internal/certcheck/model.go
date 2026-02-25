package certcheck

import (
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/model"
)

const (
	// CertRoleClient represents client certificates used for mTLS authentication
	CertRoleClient = "client"
	// CertRoleUpstream represents upstream certificates used for Gateway→Backend mTLS
	CertRoleUpstream = "upstream"

	// CertCooldownKeyPrefix is the Redis key prefix for certificate cooldowns
	CertCooldownKeyPrefix = "cert-cooldown:"
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
	ID          string
	CommonName  string
	NotAfter    time.Time
	UntilExpiry time.Duration
}

// HoursUntilExpiry returns the number of hours until the certificate expires.
// This is calculated from the UntilExpiry field for convenience.
func (c CertInfo) HoursUntilExpiry() int {
	return int(c.UntilExpiry.Hours())
}

// MinutesUntilExpiry returns the number of minutes until the certificate expires.
// This is calculated from the UntilExpiry field for convenience.
func (c CertInfo) MinutesUntilExpiry() int {
	return int(c.UntilExpiry.Minutes())
}

// SecondsUntilExpiry returns the number of seconds until the certificate expires.
// This is calculated from the UntilExpiry field for convenience.
func (c CertInfo) SecondsUntilExpiry() int {
	return int(c.UntilExpiry.Seconds())
}

// DaysUntilExpiry returns the number of days until the certificate expires.
// This is calculated from the UntilExpiry field for convenience.
func (c CertInfo) DaysUntilExpiry() int {
	return c.HoursUntilExpiry() / 24
}

// EventCertificateExpiringSoonMeta is the metadata structure for certificate expiration events.
type EventCertificateExpiringSoonMeta struct {
	model.EventMetaDefault
	CertID        string    `json:"cert_id"`
	CertName      string    `json:"cert_name"`
	ExpiresAt     time.Time `json:"expires_at"`
	DaysRemaining int       `json:"days_remaining"`
	APIID         string    `json:"api_id,omitempty"`
	CertRole      string    `json:"cert_role"` // Role: CertRoleClient or CertRoleUpstream
}

// EventCertificateExpiredMeta is the metadata structure for certificate expiration events.
type EventCertificateExpiredMeta struct {
	model.EventMetaDefault
	CertID          string    `json:"cert_id"`
	CertName        string    `json:"cert_name"`
	ExpiredAt       time.Time `json:"expired_at"`
	DaysSinceExpiry int       `json:"days_since_expiry"`
	APIID           string    `json:"api_id,omitempty"`
	CertRole        string    `json:"cert_role"` // Role: CertRoleClient or CertRoleUpstream
}
