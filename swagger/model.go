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
	Pagination paginationStatus           `json:"pagination"`
	Tokens     []gateway.OAuthClientToken `json:"tokens"`
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

func stringSchema() *openapi3.SchemaOrRef {
	stringType := openapi3.SchemaTypeString
	return &openapi3.SchemaOrRef{
		Schema: &openapi3.Schema{
			Type: &stringType,
		},
	}
}

func intSchema() *openapi3.SchemaOrRef {
	intType := openapi3.SchemaTypeInteger
	return &openapi3.SchemaOrRef{
		Schema: &openapi3.Schema{
			Type: &intType,
		},
	}
}

func resetQuotaSchema() *openapi3.SchemaOrRef {
	stringType := openapi3.SchemaTypeString
	return &openapi3.SchemaOrRef{
		Schema: &openapi3.Schema{
			Type: &stringType,
			Enum: []interface{}{"1"},
		},
	}
}

func blockSchema() *openapi3.SchemaOrRef {
	stringType := openapi3.SchemaTypeBoolean
	return &openapi3.SchemaOrRef{
		Schema: &openapi3.Schema{
			Type: &stringType,
			Enum: []interface{}{true},
		},
	}
}

func boolSchema() *openapi3.SchemaOrRef {
	boolSchema := openapi3.SchemaTypeBoolean
	return &openapi3.SchemaOrRef{
		Schema: &openapi3.Schema{
			Type: &boolSchema,
		},
	}
}

////2256b0b7877f85d9e2ecd2b7c59acd47ce8f42725ad0c5275fd4e213dddea8ad
////c332be491f0001023940dff44e6f1a9f12fb3550aee63cae3ed4fe11335790fd
