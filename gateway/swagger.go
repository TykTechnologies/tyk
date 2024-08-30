package gateway

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

// parameterBodies
// swagger:response parameterBodies
type swaggerParameterBodies struct {
	// in: body
	APIStatusMessage apiStatusMessage
	// in: body
	APIModifyKeySuccess ApiModifyKeySuccess
	// in: body
	NewClientRequest NewClientRequest
	// in: body
	APIDefinition apidef.APIDefinition
	// in: body
	SessionState user.SessionState
	// in:body
	APIAllKeys ApiAllKeys
	// in: body
	OAuthClientToken OAuthClientToken
}
