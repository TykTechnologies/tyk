package certusage

// Tracker defines the interface for certificate requirement tracking.
// This interface provides a unified contract for tracking which certificates
// are required by loaded APIs and which APIs use each certificate.
//
// Implementations track certificate usage to enable features like:
//   - Selective certificate synchronization in MDCB setups
//   - Certificate lifecycle management
//   - Dependency analysis for certificate deletion
type Tracker interface {
	// Required returns true if the certificate is used by any loaded API.
	Required(certID string) bool

	// APIs returns the IDs of APIs that use this certificate.
	APIs(certID string) []string
}
