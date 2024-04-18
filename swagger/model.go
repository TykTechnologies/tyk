package swagger

import (
	"strconv"
	"strings"

	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/gateway"
)

const applicationForm = "application/x-www-form-urlencoded"

var applicationOctetStream = "application/octet-stream"

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

type ParameterValues struct {
	Name        string
	Description string
	Type        openapi3.SchemaType
	Example     interface{}
	Required    bool
	In          openapi3.ParameterIn
}

func createParameter(value ParameterValues) openapi3.ParameterOrRef {
	if value.Type == "" {
		value.Type = openapi3.SchemaTypeString
	}
	vl := openapi3.Schema{
		Type: &value.Type,
	}
	if value.In == "" {
		value.In = openapi3.ParameterInQuery
	}
	if strings.TrimSpace(value.Description) != "" {
		vl.Description = StringPointerValue(value.Description)
	}
	return openapi3.Parameter{
		In:       value.In,
		Name:     value.Name,
		Required: &value.Required,
		Schema: &openapi3.SchemaOrRef{
			Schema: &vl,
		},
	}.ToParameterOrRef()
}

func stringEnumSchema(enums ...string) *openapi3.SchemaOrRef {
	stringType := openapi3.SchemaTypeString
	item := []interface{}{}
	for _, enum := range enums {
		item = append(item, enum)
	}
	return &openapi3.SchemaOrRef{
		Schema: &openapi3.Schema{
			Type: &stringType,
			Enum: item,
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

type HeaderCr struct {
	Key         string              `json:"key"`
	Description string              `json:"description"`
	Type        openapi3.SchemaType `json:"type"`
}

func addBinaryFormat(o3 openapi3.OperationExposer, httpStatus int) {
	code := strconv.Itoa(httpStatus)
	value, ok := o3.Operation().Responses.MapOfResponseOrRefValues[code]
	if !ok {
		return
	}
	value.Response.Content["application/octet-stream"].Schema.Schema.Format = StringPointerValue("binary")
}

func addNewResponseHeader(o3 openapi3.OperationExposer, httpStatus int, cr HeaderCr) {
	code := strconv.Itoa(httpStatus)
	value, ok := o3.Operation().Responses.MapOfResponseOrRefValues[code]
	if !ok {
		return
	}
	newHeaders := value.Response.Headers
	if newHeaders == nil {
		newHeaders = map[string]openapi3.HeaderOrRef{}
	}
	newHeaders[cr.Key] = openapi3.HeaderOrRef{
		Header: &openapi3.Header{
			Description: &cr.Description,
			Schema: &openapi3.SchemaOrRef{
				Schema: &openapi3.Schema{
					Type: &cr.Type,
				},
			},
		},
	}
	value.Response.WithHeaders(newHeaders)
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

////2256b0b7877f85d9e2ecd2b7c59acd47ce8f42725ad0c5275fd4e213dddea8ad
////c332be491f0001023940dff44e6f1a9f12fb3550aee63cae3ed4fe11335790fd
