package swagger

import "github.com/swaggest/openapi-go/openapi3"

type apiModifyKeySuccess struct {
	// in:body
	Key     string `json:"key"`
	Status  string `json:"status"`
	Action  string `json:"action"`
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

func boolSchema() *openapi3.SchemaOrRef {
	boolSchema := openapi3.SchemaTypeBoolean
	return &openapi3.SchemaOrRef{
		Schema: &openapi3.Schema{
			Type: &boolSchema,
		},
	}
}
