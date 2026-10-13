package keys

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/user"
)

// DefaultMinTokenLength is the minimum custom key length when
// min_token_length is unset; it mirrors the auth middleware's check.
const DefaultMinTokenLength = 3

// EffectiveMinTokenLength returns the configured minimum or the default.
func EffectiveMinTokenLength(configured int) int {
	if configured == 0 {
		return DefaultMinTokenLength
	}
	return configured
}

// ValidateAccessConditions rejects access rights carrying a granular access
// condition that the gateway would not be able to evaluate. Conditions fail
// closed, so an unreadable one denies every request the enclosing entry
// would otherwise have granted; reporting it here turns a silent outage on
// live traffic into an error at the point the key or policy is written.
func ValidateAccessConditions(accessRights map[string]user.AccessDefinition) error {
	// Sorted so that a payload with several bad entries always reports the
	// same one, rather than whichever the map iteration reached first.
	apiIDs := make([]string, 0, len(accessRights))
	for apiID := range accessRights {
		apiIDs = append(apiIDs, apiID)
	}
	sort.Strings(apiIDs)

	for _, apiID := range apiIDs {
		if err := user.ValidateAccessSpecs(accessRights[apiID].AllowedURLs); err != nil {
			return fmt.Errorf("access_rights[%q].%w", apiID, err)
		}
	}

	return nil
}

// HasMCPFields returns true if the access definition contains any MCP-specific fields.
func HasMCPFields(ar user.AccessDefinition) bool {
	return len(ar.JSONRPCMethods) > 0 ||
		!ar.JSONRPCMethodsAccessRights.IsEmpty() ||
		len(ar.MCPPrimitives) > 0 ||
		!ar.MCPAccessRights.IsEmpty()
}

// HasNonMCPFields returns true if the access definition contains any
// HTTP/REST or GraphQL fields that have no meaning in the MCP protocol.
func HasNonMCPFields(ar user.AccessDefinition) bool {
	return len(ar.AllowedURLs) > 0 ||
		len(ar.Endpoints) > 0 ||
		len(ar.RestrictedTypes) > 0 ||
		len(ar.AllowedTypes) > 0 ||
		ar.DisableIntrospection ||
		len(ar.FieldAccessRights) > 0
}

// ValidateMCPFieldsInAccessRights returns an error if any MCP-specific
// fields are set on an access right whose API is known and is not an MCP
// proxy. Unknown APIs are skipped to avoid false negatives during bootstrap.
func (s *Service) ValidateMCPFieldsInAccessRights(accessRights map[string]user.AccessDefinition) error {
	for apiID, ar := range accessRights {
		if !HasMCPFields(ar) {
			continue
		}
		api, ok := s.d.APIs.APIByID(apiID)
		if !ok {
			continue
		}
		if !api.IsMCP {
			return fmt.Errorf("MCP fields can only be configured on MCP Proxies, API %q is not an MCP Proxy", apiID)
		}
		for _, p := range ar.MCPPrimitives {
			if err := p.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateNonMCPFieldsOnMCPProxy returns an error if HTTP/REST or GraphQL
// access-right fields are set on a known MCP proxy. Unknown APIs are
// skipped (fail-open).
func (s *Service) ValidateNonMCPFieldsOnMCPProxy(accessRights map[string]user.AccessDefinition) error {
	for apiID, ar := range accessRights {
		if !HasNonMCPFields(ar) {
			continue
		}
		api, ok := s.d.APIs.APIByID(apiID)
		if !ok {
			continue
		}
		if api.IsMCP {
			return fmt.Errorf("HTTP/REST and GraphQL fields cannot be configured on MCP Proxies, API %q is an MCP Proxy", apiID)
		}
	}
	return nil
}

// ValidateMtlsStaticCertificateBindings validates that all certificate IDs
// in mtls_static_certificate_bindings belong to the org and exist.
func (s *Service) ValidateMtlsStaticCertificateBindings(certIDs []string, orgID string) error {
	if len(certIDs) == 0 {
		return nil
	}

	// Validate certificate IDs start with orgID prefix to prevent path traversal attacks
	// Certificate IDs follow the pattern: orgID + sha256hash
	for _, certID := range certIDs {
		if orgID != "" && !strings.HasPrefix(certID, orgID) {
			return fmt.Errorf("invalid certificate ID: %s", certID)
		}
	}

	if s.d.Certs == nil {
		return fmt.Errorf("certificate not found: %s", certIDs[0])
	}

	// Use List() for efficient batch validation - single storage operation
	certificates := s.d.Certs.List(certIDs, certs.CertificateAny)

	// List returns nil for missing certs
	for i, cert := range certificates {
		if cert == nil {
			return fmt.Errorf("certificate not found: %s", certIDs[i])
		}
	}

	return nil
}

// NewCertIDs returns only the certificate IDs that are in newCerts but not
// in originalCerts, so updates validate only newly added certificates.
func NewCertIDs(originalCerts, newCerts []string) []string {
	if len(originalCerts) == 0 {
		return newCerts
	}

	existingCerts := make(map[string]struct{}, len(originalCerts))
	for _, certID := range originalCerts {
		existingCerts[certID] = struct{}{}
	}

	var newCertIDs []string
	for _, certID := range newCerts {
		if _, exists := existingCerts[certID]; !exists {
			newCertIDs = append(newCertIDs, certID)
		}
	}

	return newCertIDs
}
