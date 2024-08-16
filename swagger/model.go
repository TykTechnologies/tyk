package swagger

import (
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/gateway"
)

type paginationStatus struct {
	PageNum   int `json:"page_num"`
	PageTotal int `json:"page_total"`
	PageSize  int `json:"page_size"`
}

type paginatedOAuthClientTokens struct {
	Pagination paginationStatus           `json:"Pagination"`
	Tokens     []gateway.OAuthClientToken `json:"Tokens"`
}

type apiModifyKeySuccess struct {
	// in:body
	Key     string `json:"key" example:"b13d928b9972bd18"`
	Status  string `json:"status" example:"ok"`
	Action  string `json:"action" example:"modified"`
	KeyHash string `json:"key_hash,omitempty"`
}

type apiStatusMessage struct {
	Status string `json:"status"`
	// Response details
	Message string `json:"message"`
}

type apiAllKeys struct {
	APIKeys []string `json:"keys"`
}

type ParameterValues struct {
	Name        string
	Description string
	Type        openapi3.SchemaType
	Example     interface{}
	Required    bool
	In          openapi3.ParameterIn
}

type HeaderCr struct {
	Key         string              `json:"key"`
	Description string              `json:"description"`
	Type        openapi3.SchemaType `json:"type"`
}

func StringPointerValue(value string) *string {
	return &value
}

type Revoke struct {
	Token         string `json:"token" formData:"token" description:"token to be revoked" required:"true"`
	TokenTypeHint string `json:"token_type_hint" formData:"token_type_hint" description:"type of token to be revoked, if sent then the accepted values are access_token and refresh_token. String value and optional, of not provided then it will attempt to remove access and refresh tokens that matches"`
	ClientID      string `json:"client_id" formData:"client_id" description:"id of oauth client" required:"true"`
	OrgID         string `json:"org_id" formData:"org_id"`
}
