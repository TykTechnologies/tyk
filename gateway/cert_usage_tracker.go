package gateway

import "sync"

// certUsageTracker tracks which certificates are required by loaded APIs.
type certUsageTracker struct {
	mu sync.RWMutex

	apis map[string]map[string]struct{} // certID -> set of API IDs using this cert
}

func newCertUsageTracker() *certUsageTracker {
	return &certUsageTracker{
		apis: make(map[string]map[string]struct{}),
	}
}

// Required returns true if the certificate is used by any loaded API.
func (cr *certUsageTracker) Required(certID string) bool {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	_, exists := cr.apis[certID]
	return exists
}

// APIs returns the IDs of APIs that use this certificate.
func (cr *certUsageTracker) APIs(certID string) []string {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	apiSet := cr.apis[certID]
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
func (cr *certUsageTracker) Register(spec *APISpec) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	apiID := spec.APIID
	certSet := make(map[string]struct{})

	// Collect all certificate references (using set to auto-deduplicate)
	for _, certID := range spec.Certificates {
		if certID != "" {
			certSet[certID] = struct{}{}
		}
	}
	for _, certID := range spec.ClientCertificates {
		if certID != "" {
			certSet[certID] = struct{}{}
		}
	}
	for _, certID := range spec.UpstreamCertificates {
		if certID != "" {
			certSet[certID] = struct{}{}
		}
	}
	for _, certID := range spec.PinnedPublicKeys {
		if certID != "" {
			certSet[certID] = struct{}{}
		}
	}

	// Track API association for each cert
	for certID := range certSet {
		// Initialize the set if it doesn't exist
		if cr.apis[certID] == nil {
			cr.apis[certID] = make(map[string]struct{})
		}
		cr.apis[certID][apiID] = struct{}{}
	}
}

// RegisterServerCerts tracks gateway server certificates.
func (cr *certUsageTracker) RegisterServerCerts(certIDs []string) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	const serverAPI = "__server__"

	for _, certID := range certIDs {
		if certID == "" {
			continue
		}

		// Initialize the set if it doesn't exist
		if cr.apis[certID] == nil {
			cr.apis[certID] = make(map[string]struct{})
		}
		cr.apis[certID][serverAPI] = struct{}{}
	}
}

// Reset clears all tracked certificates.
func (cr *certUsageTracker) Reset() {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	for k := range cr.apis {
		delete(cr.apis, k)
	}
}

// Len returns the number of required certificates.
func (cr *certUsageTracker) Len() int {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return len(cr.apis)
}

// Certs returns all required certificate IDs.
func (cr *certUsageTracker) Certs() []string {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	ids := make([]string, 0, len(cr.apis))
	for id := range cr.apis {
		ids = append(ids, id)
	}
	return ids
}
