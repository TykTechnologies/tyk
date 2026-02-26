package gateway

import "sync"

// certUsageTracker tracks which certificates are required by loaded APIs and active tokens.
//
// It maintains two separate maps with independent lifecycles:
//   - apiCerts: certs referenced by API definitions, replaced atomically on every loadApps call.
//   - tokenCerts: certs bound to session/token objects (Certificate Auth / dynamic mTLS),
//     updated incrementally as tokens are synced or deleted.
//
// Required() returns true when a cert appears in either map, so the selective-sync filter
// in CertificateManager.GetRaw allows through both kinds of cert.
type certUsageTracker struct {
	mu sync.RWMutex

	apiCerts   map[string]map[string]struct{} // certID -> set of API IDs
	tokenCerts map[string]map[string]struct{} // certID -> set of token keys
}

func newUsageTracker() *certUsageTracker {
	return &certUsageTracker{
		apiCerts:   make(map[string]map[string]struct{}),
		tokenCerts: make(map[string]map[string]struct{}),
	}
}

// Required returns true if the certificate is needed by any loaded API or active token.
func (cr *certUsageTracker) Required(certID string) bool {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	_, inAPI := cr.apiCerts[certID]
	_, inToken := cr.tokenCerts[certID]
	return inAPI || inToken
}

// APIs returns the IDs of APIs that reference this certificate.
func (cr *certUsageTracker) APIs(certID string) []string {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	apiSet := cr.apiCerts[certID]
	if apiSet == nil {
		return nil
	}

	result := make([]string, 0, len(apiSet))
	for apiID := range apiSet {
		result = append(result, apiID)
	}
	return result
}

// extractCertificatesFromSpec collects all certificate IDs from an API spec.
func extractCertificatesFromSpec(spec *APISpec) map[string]struct{} {
	certSet := make(map[string]struct{})

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

	return certSet
}

// ReplaceAll atomically replaces the API-sourced certificate usage map.
// Token cert entries are preserved across reloads.
func (cr *certUsageTracker) ReplaceAll(newApis map[string]map[string]struct{}) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	cr.apiCerts = newApis
}

// TrackTokenCerts registers the certificates bound to a token/session into the tracker.
// tokenKey is an opaque identifier for the token (used to associate the entry).
// certIDs is the set of cert IDs to register (Certificate and MtlsStaticCertificateBindings).
func (cr *certUsageTracker) TrackTokenCerts(tokenKey string, certIDs []string) {
	if len(certIDs) == 0 {
		return
	}
	cr.mu.Lock()
	defer cr.mu.Unlock()

	for _, certID := range certIDs {
		if certID == "" {
			continue
		}
		if cr.tokenCerts[certID] == nil {
			cr.tokenCerts[certID] = make(map[string]struct{})
		}
		cr.tokenCerts[certID][tokenKey] = struct{}{}
	}
}

// UntrackTokenCerts removes all token cert associations for the given tokenKey.
// Entries whose token set becomes empty are removed from the map.
func (cr *certUsageTracker) UntrackTokenCerts(tokenKey string) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	for certID, tokens := range cr.tokenCerts {
		delete(tokens, tokenKey)
		if len(tokens) == 0 {
			delete(cr.tokenCerts, certID)
		}
	}
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

		for certID := range certSet {
			if usageMap[certID] == nil {
				usageMap[certID] = make(map[string]struct{})
			}
			usageMap[certID][apiID] = struct{}{}
		}
	}

	return usageMap
}

// Len returns the total number of distinct required certificates across both maps.
func (cr *certUsageTracker) Len() int {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	seen := make(map[string]struct{}, len(cr.apiCerts)+len(cr.tokenCerts))
	for certID := range cr.apiCerts {
		seen[certID] = struct{}{}
	}
	for certID := range cr.tokenCerts {
		seen[certID] = struct{}{}
	}
	return len(seen)
}

// Certs returns all required certificate IDs from both maps.
func (cr *certUsageTracker) Certs() []string {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	seen := make(map[string]struct{}, len(cr.apiCerts)+len(cr.tokenCerts))
	for certID := range cr.apiCerts {
		seen[certID] = struct{}{}
	}
	for certID := range cr.tokenCerts {
		seen[certID] = struct{}{}
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	return ids
}
