//go:build !ee && !dev

package gateway

import (
	"github.com/TykTechnologies/tyk/apidef"
)

// augmentFederationSchema is the CE no-op for the Apollo Federation v2 schema
// augmentation step. The real implementation lives in mw_graphql_federation_ee.go
// and is selected by the `ee` or `dev` build tag.
//
// In CE builds, federation features are disabled. If the customer has declared
// `@key` directives in their SDL, a warning is emitted pointing them at the EE
// build; the SDL is returned unchanged.
func (m *GraphQLMiddleware) augmentFederationSchema(schemaStr string, _ apidef.GraphQLExecutionMode) (string, error) {
	if schemaHasKeyDirective(schemaStr) {
		log.Warnf("API %s declares `@key` directives but Apollo Federation v2 features are only available in Tyk EE; the directives are ignored", m.Spec.APIID)
	}
	return schemaStr, nil
}
