package gateway

import "sync"

// certRegistry tracks which certificates are required by loaded APIs.
type certRegistry struct {
	mu sync.RWMutex

	required   map[string]bool                // certID -> is required
	apisByCert map[string]map[string]bool     // certID -> set of API IDs using this cert
	certsByAPI map[string]map[string]bool     // API ID -> set of cert IDs it uses
}

func newCertRegistry() *certRegistry {
	return &certRegistry{
		required:   make(map[string]bool),
		apisByCert: make(map[string]map[string]bool),
		certsByAPI: make(map[string]map[string]bool),
	}
}

// Required returns true if the certificate is used by any loaded API.
func (cr *certRegistry) Required(certID string) bool {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.required[certID]
}

// APIs returns the IDs of APIs that use this certificate.
func (cr *certRegistry) APIs(certID string) []string {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	apiSet := cr.apisByCert[certID]
	if apiSet == nil {
		return nil
	}

	// Convert set to slice
	result := make([]string, 0, len(apiSet))
	for apiID := range apiSet {
		result = append(result, apiID)
	}
	return result
}

// Register extracts and tracks all certificates from an API spec.
func (cr *certRegistry) Register(spec *APISpec) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	apiID := spec.APIID
	certSet := make(map[string]bool)

	// Collect all certificate references (using set to auto-deduplicate)
	for _, certID := range spec.Certificates {
		if certID != "" {
			certSet[certID] = true
		}
	}
	for _, certID := range spec.ClientCertificates {
		if certID != "" {
			certSet[certID] = true
		}
	}
	for _, certID := range spec.UpstreamCertificates {
		if certID != "" {
			certSet[certID] = true
		}
	}
	for _, certID := range spec.PinnedPublicKeys {
		if certID != "" {
			certSet[certID] = true
		}
	}

	cr.certsByAPI[apiID] = certSet

	// Mark each cert as required and track API association
	for certID := range certSet {
		cr.required[certID] = true

		// Initialize the set if it doesn't exist
		if cr.apisByCert[certID] == nil {
			cr.apisByCert[certID] = make(map[string]bool)
		}
		cr.apisByCert[certID][apiID] = true
	}
}

// RegisterServerCerts tracks gateway server certificates.
func (cr *certRegistry) RegisterServerCerts(certIDs []string) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	const serverAPI = "__server__"

	for _, certID := range certIDs {
		if certID == "" {
			continue
		}

		cr.required[certID] = true

		// Initialize the set if it doesn't exist
		if cr.apisByCert[certID] == nil {
			cr.apisByCert[certID] = make(map[string]bool)
		}
		cr.apisByCert[certID][serverAPI] = true
	}
}

// Reset clears all tracked certificates.
func (cr *certRegistry) Reset() {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	for k := range cr.required {
		delete(cr.required, k)
	}
	for k := range cr.apisByCert {
		delete(cr.apisByCert, k)
	}
	for k := range cr.certsByAPI {
		delete(cr.certsByAPI, k)
	}
}

// Len returns the number of required certificates.
func (cr *certRegistry) Len() int {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return len(cr.required)
}

// Certs returns all required certificate IDs.
func (cr *certRegistry) Certs() []string {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	ids := make([]string, 0, len(cr.required))
	for id := range cr.required {
		ids = append(ids, id)
	}
	return ids
}
