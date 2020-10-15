package gateway

import (
	"github.com/TykTechnologies/tyk/v3/apidef"
	"github.com/TykTechnologies/tyk/v3/user"
)

// parameterBodies
// swagger:response parameterBodies
type swaggerParameterBodies struct {
	// in: body
	APIStatusMessage apiStatusMessage
	// in: body
	APIModifyKeySuccess apiModifyKeySuccess
	// in: body
	NewClientRequest NewClientRequest
	// in: body
	APIDefinition apidef.APIDefinition
	// in: body
	SessionState user.SessionState
	// in:body
	APIAllKeys apiAllKeys
	// in: body
	OAuthClientToken OAuthClientToken
}
