package gateway

import (
	"sync"

	"github.com/TykTechnologies/tyk/certs"
)

// certUsageTracker tracks which certificates are required by loaded APIs.
type certUsageTracker struct {
	mu sync.RWMutex

	apis map[string]map[string]struct{} // certID -> set of API IDs using this cert
}

func newUsageTracker() *certUsageTracker {
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

// extractCertificatesFromSpec collects all certificate IDs from an API spec.
//
// Inline PEM values (recognised by certs.IsPEMContent) are deliberately
// excluded: the usage tracker exists to drive RPC/MDCB cert sync, and
// embedded PEMs are inline content that doesn't need to be fetched or
// synced. Including them would also bloat the map with multi-KB string
// keys.
func extractCertificatesFromSpec(spec *APISpec) map[string]struct{} {
	certSet := make(map[string]struct{})

	addID := func(certID string) {
		if certID == "" || certs.IsPEMContent(certID) {
			return
		}
		certSet[certID] = struct{}{}
	}

	// Collect all certificate references (using set to auto-deduplicate)
	for _, certID := range spec.Certificates {
		addID(certID)
	}
	for _, certID := range spec.ClientCertificates {
		addID(certID)
	}
	for _, certID := range spec.UpstreamCertificates {
		addID(certID)
	}
	for _, certID := range spec.PinnedPublicKeys {
		addID(certID)
	}

	return certSet
}

// ReplaceAll atomically replaces the entire certificate usage map.
// This method is thread-safe and ensures no partial state is visible to concurrent readers.
func (cr *certUsageTracker) ReplaceAll(newApis map[string]map[string]struct{}) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	cr.apis = newApis
}

// CollectCertUsageMap creates a new certificate usage map from API specs and server certs.
// This is a helper function for building a complete usage map offline before atomic replacement.
func CollectCertUsageMap(specs []*APISpec, serverCerts []string) map[string]map[string]struct{} {
	usageMap := make(map[string]map[string]struct{})

	// Register server certificates
	const serverAPI = "__server__"
	for _, certID := range serverCerts {
		if certID == "" {
			continue
		}
		if usageMap[certID] == nil {
			usageMap[certID] = make(map[string]struct{})
		}
		usageMap[certID][serverAPI] = struct{}{}
	}

	// Register certificates from each API spec
	for _, spec := range specs {
		apiID := spec.APIID
		certSet := extractCertificatesFromSpec(spec)

		// Track API association for each cert
		for certID := range certSet {
			if usageMap[certID] == nil {
				usageMap[certID] = make(map[string]struct{})
			}
			usageMap[certID][apiID] = struct{}{}
		}
	}

	return usageMap
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
