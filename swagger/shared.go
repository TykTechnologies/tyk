package swagger

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/swaggest/jsonschema-go"
	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"
)

var ErrOperationExposer = errors.New("object is not of type openapi3.OperationExposer")

const (
	applicationForm            = "application/x-www-form-urlencoded"
	applicationOctetStream     = "application/octet-stream"
	applicationJSON            = "application/json"
	oasExample                 = "oasExample"
	oasExampleList             = "oasExampleList"
	certificateMetaExample     = "certificateMetaExample"
	certificateMetaListExample = "certificateMetaListExample"
	certIdList                 = "certIdList"
	certificateBasicList       = "certificateBasicList"
	policiesExample            = "policiesExample"
	UpstreamURL                = "UpstreamURL"
	ListenPath                 = "ListenPath"
	CustomDomain               = "CustomDomain"
	AllowList                  = "AllowList"
	ValidateRequest            = "ValidateRequest"
	MockResponse               = "MockResponse"
	Authentication             = "Authentication"
	TemplateID                 = "TemplateID"
	SearchText                 = "SearchText"
	AccessType                 = "AccessType"
	policyRequestObject        = "policyRequestObject"
	tokenListExample           = "tokenListExample"
	paginatedTokenExample      = "paginatedTokenExample"
)

type BinaryExample string

type (
	ExampleType int
	ItemType    int
	AllOfOneOf  int
)

const (
	Inline ExampleType = iota
	External
	Component
)

const (
	OneOf AllOfOneOf = iota
	AllOff
)

const (
	InlineType ItemType = iota
	ExternalType
	ComponentType
)

func RefExamples(r *openapi3.Reflector) {
	addRefExample(r, oasExample, oasSample(OasSampleString()))
	addRefExample(r, certificateMetaExample, certificates[0])
	addRefExample(r, certificateMetaListExample, certificates)
	addRefExample(r, certIdList, certListId)
	addRefExample(r, certificateBasicList, certificateBasic)
	addRefExample(r, policiesExample, policies)
	addRefExample(r, tokenListExample, listTokens)
	addRefExample(r, paginatedTokenExample, paginatedOAuthClientTokens{
		Pagination: paginationStatus{
			PageNum:   1,
			PageTotal: 0,
			PageSize:  100,
		},
		Tokens: listTokens,
	})
	addRefExample(r, oasExampleList, []map[string]interface{}{oasSample(OasSampleString())})
	///addRefExample(r,policyRequestObject,minimalPolicies)
	// addRefExample(r, stringOasExample, OasSampleString())

	///addRefExample(r, graphResponseExample, graphDetails())
	//addRefExample(r, keySingleApiDef, fullApiReturned())
	///addRefExample(r, keyPaginatedApiExamples, paginatedApiExample())
	///addRefExample(r, keyAggregateAnalytics, aggregateAnalyticsData())
	///addRefExample(r, keyRequestsResponseExampleKey, responseData)
	//addTag("Organisations", "Organisations Management", optionalTagParameters{})
	//addTag("Data Graph APIs", "Data Graph Import APIs", optionalTagParameters{})
}

func RefParameters(r *openapi3.Reflector) {
	str := openapi3.SchemaTypeString
	boolRef := "#/components/schemas/BooleanQueryParam"
	stringSchema := &openapi3.SchemaOrRef{
		Schema: &openapi3.Schema{
			Type: &str,
		},
	}

	addRefParameters(r, UpstreamURL, openapi3.Parameter{
		Description: PointerValue("Upstream URL for the API"),
		Name:        "upstreamURL",
		In:          openapi3.ParameterInQuery,
		Schema:      stringSchema,
		Required:    PointerValue(false),
		Example:     valueToInterface("https://localhost:8080"),
	})
	addRefParameters(r, ListenPath, openapi3.Parameter{
		Description: PointerValue("Listen path for the API"),
		Name:        "listenPath",
		Schema:      stringSchema,
		In:          openapi3.ParameterInQuery,
		Required:    PointerValue(false),
		Example:     valueToInterface("/user-test/"),
	})
	addRefParameters(r, CustomDomain, openapi3.Parameter{
		Description: PointerValue("Custom domain for the API"),
		Name:        "customDomain",
		Schema:      stringSchema,
		Required:    PointerValue(false),
		In:          openapi3.ParameterInQuery,
		Example:     valueToInterface("tyk.io"),
	})
	addRefParameters(r, ValidateRequest, openapi3.Parameter{
		Description: PointerValue("Enable validateRequest middleware for all endpoints having a request body with media type application/json"),
		Name:        "validateRequest",
		In:          openapi3.ParameterInQuery,
		Required:    PointerValue(false),
		Schema: &openapi3.SchemaOrRef{
			SchemaReference: &openapi3.SchemaReference{
				Ref: boolRef,
			},
		},
	})
	addRefParameters(r, MockResponse, openapi3.Parameter{
		Description: PointerValue("Enable mockResponse middleware for all endpoints having responses configured."),
		Name:        "mockResponse",
		In:          openapi3.ParameterInQuery,
		Required:    PointerValue(false),
		Schema: &openapi3.SchemaOrRef{
			SchemaReference: &openapi3.SchemaReference{
				Ref: boolRef,
			},
		},
	})
	addRefParameters(r, AllowList, openapi3.Parameter{
		Description: PointerValue("Enable allowList middleware for all endpoints"),
		Name:        "allowList",
		Required:    PointerValue(false),
		In:          openapi3.ParameterInQuery,
		Schema: &openapi3.SchemaOrRef{
			SchemaReference: &openapi3.SchemaReference{
				Ref: boolRef,
			},
		},
	})
	addRefParameters(r, Authentication, openapi3.Parameter{
		Description: PointerValue("Enable/disable the authentication mechanism in your Tyk Gateway for your OAS API"),
		Name:        "authentication",
		In:          openapi3.ParameterInQuery,
		Schema: &openapi3.SchemaOrRef{
			SchemaReference: &openapi3.SchemaReference{
				Ref: boolRef,
			},
		},
	})

	/*addRefParameters(r, TemplateID, openapi3.Parameter{
		Name:        "templateID",
		Schema:      stringSchema,
		In:          openapi3.ParameterInQuery,
		Example:     valueToInterface("my-unique-template-id"),
		Description: PointerValue("The asset ID of template applied while creating or importing an OAS API."),
	})*/
	addRefParameters(r, SearchText, openapi3.Parameter{
		Name:        "searchText",
		Required:    PointerValue(false),
		Schema:      stringSchema,
		In:          openapi3.ParameterInQuery,
		Example:     valueToInterface("Sample oas"),
		Description: PointerValue("Search for API version name"),
	})
	addRefParameters(r, AccessType, openapi3.Parameter{
		Required: PointerValue(false),
		Name:     "accessType",
		Schema: &openapi3.SchemaOrRef{
			Schema: &openapi3.Schema{
				Type: &str,
				Enum: []interface{}{"internal", "external"},
			},
		},
		In:          openapi3.ParameterInQuery,
		Example:     valueToInterface("internal"),
		Description: PointerValue("Filter for internal or external API versions"),
	})
}

func AddRefComponent(r *openapi3.Reflector) {
	if r.Spec.ComponentsEns().SchemasEns().MapOfSchemaOrRefValues == nil {
		r.Spec.ComponentsEns().SchemasEns().MapOfSchemaOrRefValues = map[string]openapi3.SchemaOrRef{}
	}
	boolSchema := openapi3.SchemaTypeBoolean
	r.Spec.ComponentsEns().SchemasEns().MapOfSchemaOrRefValues["BooleanQueryParam"] = openapi3.SchemaOrRef{
		Schema: &openapi3.Schema{
			Type:    &boolSchema,
			Example: valueToInterface(true),
			Enum:    []interface{}{true, false},
		},
	}
	// r.Spec.ComponentsEns().SchemasEns().MapOfSchemaOrRefValues[""]=openapi3.SchemaOrRef{
	//	Schema:          openapi,
	//	}
}

func addRefParameters(r *openapi3.Reflector, key string, parameter openapi3.Parameter) {
	if r.Spec.ComponentsEns().ParametersEns().MapOfParameterOrRefValues == nil {
		r.Spec.ComponentsEns().ParametersEns().MapOfParameterOrRefValues = map[string]openapi3.ParameterOrRef{}
	}
	r.Spec.Components.ParametersEns().MapOfParameterOrRefValues[key] = parameter.ToParameterOrRef()
}

func addRefExample(r *openapi3.Reflector, name string, object interface{}) {
	if r.Spec.ComponentsEns().ExamplesEns().MapOfExampleOrRefValues == nil {
		r.Spec.ComponentsEns().ExamplesEns().MapOfExampleOrRefValues = map[string]openapi3.ExampleOrRef{}
	}
	r.Spec.Components.ExamplesEns().MapOfExampleOrRefValues[name] = openapi3.ExampleOrRef{
		Example: &openapi3.Example{
			Value: valueToInterface(object),
		},
	}
}

func addRefSchema(r *openapi3.Reflector) {
}

func addTykOasDefinition(r *openapi3.Reflector, name string, object interface{}) {
	if r.Spec.ComponentsEns().SchemasEns().MapOfSchemaOrRefValues == nil {
		r.Spec.ComponentsEns().SchemasEns().MapOfSchemaOrRefValues = map[string]openapi3.SchemaOrRef{}
	}
	r.Spec.ComponentsEns().SchemasEns().MapOfSchemaOrRefValues["TykOasApiDefinition"] = openapi3.SchemaOrRef{}
}

func addOperations(r *openapi3.Reflector, operations ...func(r *openapi3.Reflector) error) error {
	for _, operation := range operations {
		err := operation(r)
		if err != nil {
			return err
		}
	}
	return nil
}

type OperationWithExample struct {
	oc                      openapi.OperationContext
	respExamples            []ExampleObject
	oneOfExamples           []multipleExamplesValues
	oneOfAllOfResponseItems []multipleExamplesValues
	reqExamples             *ExampleObject
	multipleRequestOneOf    []ReqOneOfAllOf
	respHeaders             map[string]openapi3.HeaderOrRef
	r                       *openapi3.Reflector
	parameters              []openapi3.ParameterOrRef
	pattern                 string
	externalRequest         *ExternalRef
	externalResponse        []ExternalRef
	binaryFormat            []BinaryFormat
	multipleRequestExamples []ExternalRef
}

type SafeOperation struct {
	Method, PathPattern, OperationID, Tag string
}

func NewOperationWithSafeExample(r *openapi3.Reflector, operation SafeOperation) (*OperationWithExample, error) {
	return NewOperationWithExamples(r, operation.Method, operation.PathPattern, operation.OperationID, operation.Tag)
}

func NewOperationWithExamples(r *openapi3.Reflector, method, pathPattern, operationID, tag string) (*OperationWithExample, error) {
	oc, err := r.NewOperationContext(method, pathPattern)
	if err != nil {
		return nil, err
	}
	op := OperationWithExample{
		oc:           oc,
		respExamples: []ExampleObject{},
		r:            r,
		pattern:      pathPattern,
	}
	op.oc.SetID(operationID)
	op.oc.SetTags(tag)
	///op.StatusUnauthorized()
	op.StatusForbidden()
	return &op, err
}

func (op *OperationWithExample) SetSummary(summary string) {
	op.oc.SetSummary(summary)
}

func (op *OperationWithExample) SetDescription(summary string) {
	op.oc.SetDescription(summary)
}

func (op *OperationWithExample) AddResp(object interface{}, httpStatus int, options ...openapi.ContentOption) {
	options = append(options, openapi.WithHTTPStatus(httpStatus))
	op.oc.AddRespStructure(object, options...)
}

func (op *OperationWithExample) addExternalResponse(ref ExternalRef) {
	op.externalResponse = append(op.externalResponse, ref)
}

func (op *OperationWithExample) AddResponseHeaders(header ResponseHeader) {
	if header.Type == nil {
		header.Type = PointerValue(openapi3.SchemaTypeString)
	}
	he := openapi3.HeaderOrRef{
		Header: &openapi3.Header{
			Description: header.Description,
			Schema: &openapi3.SchemaOrRef{
				Schema: &openapi3.Schema{
					Type: header.Type,
				},
			},
		},
	}
	if (op.respHeaders) == nil {
		op.respHeaders = map[string]openapi3.HeaderOrRef{}
	}
	op.respHeaders[header.Name] = he
}

func (op *OperationWithExample) AddGenericErrorResponse(httpStatus int, message string, options ...openapi.ContentOption) {
	errResp := apiStatusMessage{
		Status:  "error",
		Message: message,
	}
	op.AddRespWithExample(errResp, httpStatus, options...)
}

func (op *OperationWithExample) AddRefParameters(name string) {
	ref := fmt.Sprintf("#/components/parameters/%s", name)
	par := openapi3.ParameterOrRef{
		ParameterReference: &openapi3.ParameterReference{Ref: ref},
	}
	op.parameters = append(op.parameters, par)
}

func (op *OperationWithExample) AddParameter(name, description string, In openapi3.ParameterIn, optionalPams OptionalParameterValues) {
	if optionalPams.Type == "" {
		optionalPams.Type = openapi3.SchemaTypeString
	}
	vl := openapi3.Schema{
		Type: &optionalPams.Type,
	}
	if optionalPams.Default != nil {
		vl.Default = optionalPams.Default
	}
	if (len(optionalPams.Enum)) > 0 {
		vl.Enum = optionalPams.Enum
	}
	par := openapi3.Parameter{
		Name:        name,
		In:          In,
		Description: PointerValue(description),
		Required:    optionalPams.Required,
		Deprecated:  optionalPams.Deprecated,
		Schema: &openapi3.SchemaOrRef{
			Schema: &vl,
		},
	}
	if optionalPams.AllowEmptyValue {
		par.AllowEmptyValue = &optionalPams.AllowEmptyValue
	}
	if optionalPams.Example != nil {
		par.Example = optionalPams.Example
	}
	if len(optionalPams.MultipleExamples) > 0 {
		examples := par.Examples
		if examples == nil {
			examples = make(map[string]openapi3.ExampleOrRef)
		}
		for index := range optionalPams.MultipleExamples {
			examples[optionalPams.MultipleExamples[index].key] = openapi3.ExampleOrRef{
				Example: &openapi3.Example{
					Summary: &optionalPams.MultipleExamples[index].Summary,
					Value:   &optionalPams.MultipleExamples[index].object,
				},
			}
		}
		par.Examples = examples
	}
	op.parameters = append(op.parameters, par.ToParameterOrRef())
}

func (op *OperationWithExample) AddQueryParameter(name, description string, optionalPams OptionalParameterValues) {
	if optionalPams.Required == nil {
		optionalPams.Required = PointerValue(false)
	}
	op.AddParameter(name, description, openapi3.ParameterInQuery, optionalPams)
}

func (op *OperationWithExample) AddPathParameter(name, description string, optionalPams OptionalParameterValues) {
	if optionalPams.Required == nil {
		optionalPams.Required = PointerValue(true)
	}
	op.AddParameter(name, description, openapi3.ParameterInPath, optionalPams)
}

type OptionalParameterValues struct {
	Required         *bool
	Example          *interface{}
	Type             openapi3.SchemaType
	Enum             []interface{}
	Deprecated       *bool `json:"deprecated,omitempty"`
	Default          *interface{}
	MultipleExamples []multipleExamplesValues
	AllowEmptyValue  bool
}

func (op *OperationWithExample) StatusUnauthorized() {
	op.AddGenericErrorResponse(http.StatusUnauthorized, "Not authorised")
}

func (op *OperationWithExample) StatusForbidden(options ...openapi.ContentOption) {
	message := fmt.Sprintf("Attempted administrative access with invalid or missing key!")
	op.AddGenericErrorResponse(http.StatusForbidden, message, options...)
}

func (op *OperationWithExample) StatusBadRequest(message string, options ...openapi.ContentOption) {
	op.AddGenericErrorResponse(http.StatusBadRequest, message, options...)
}

func (op *OperationWithExample) StatusNotFound(message string, options ...openapi.ContentOption) {
	op.AddGenericErrorResponse(http.StatusNotFound, message, options...)
}

func (op *OperationWithExample) StatusInternalServerError(message string) {
	op.AddGenericErrorResponse(http.StatusInternalServerError, message, func(cu *openapi.ContentUnit) {
		cu.Description = "Internal server error."
	})
}

func (op *OperationWithExample) AddPageQueryParameter() {
	op.AddQueryParameter("page", "Use page query parameter to say which page number you want returned.", OptionalParameterValues{
		Example: valueToInterface(1),
		Type:    openapi3.SchemaTypeInteger,
		Default: valueToInterface(1),
	})
}

func (op *OperationWithExample) AddResponseWithSeparateExample(object interface{}, httpStatus int, example interface{}, options ...openapi.ContentOption) {
	op.AddResp(object, httpStatus, options...)
	op.respExamples = append(op.respExamples, ExampleObject{
		object:     example,
		httpStatus: httpStatus,
	})
}

func (op *OperationWithExample) AddRespWithExample(object interface{}, httpStatus int, options ...openapi.ContentOption) {
	op.AddResp(object, httpStatus, options...)
	op.respExamples = append(op.respExamples, ExampleObject{
		object:     object,
		httpStatus: httpStatus,
	})
}

func (op *OperationWithExample) AddBinaryFormatResp(format BinaryFormat) {
	op.binaryFormat = append(op.binaryFormat, format)
}

func (op *OperationWithExample) AddGenericStatusOk(message string, options ...openapi.ContentOption) {
	op.AddRespWithExample(apiStatusMessage{
		Message: message,
		Status:  "ok",
	}, http.StatusOK, options...)
}

func (op *OperationWithExample) AddRespWithRefExamples(httpStatus int, object interface{}, values []multipleExamplesValues, options ...openapi.ContentOption) {
	op.AddResp(object, httpStatus, options...)
	for i := range values {
		values[i].httpStatus = httpStatus
		op.oneOfExamples = append(op.oneOfExamples, values[i])
	}
}

func (op *OperationWithExample) AddOneOfAllOfRespWithExamples(itemType AllOfOneOf, httpStatus int, items []multipleExamplesValues, options ...openapi.ContentOption) {
	var inlineItems []interface{}
	for i := range items {
		if items[i].objectType == InlineType {
			inlineItems = append(inlineItems, items[i].object)
		}
		items[i].AllOfOneOf = itemType
	}
	if len(inlineItems) != 0 {
		if itemType == AllOff {
			op.oc.AddRespStructure(jsonschema.AllOf(inlineItems...), options...)
		} else {
			op.oc.AddRespStructure(jsonschema.OneOf(inlineItems...), options...)
		}
	}
	///op.oc.AddRespStructure(jsonschema.OneOf(items...), options...)
	for i := range items {
		items[i].httpStatus = httpStatus
		ite := items[i]
		if ite.hasExample {
			op.oneOfExamples = append(op.oneOfExamples, items[i])
		}
	}
	op.oneOfAllOfResponseItems = append(op.oneOfAllOfResponseItems, items...)
}

func (op *OperationWithExample) AddReqWithExample(object interface{}, options ...openapi.ContentOption) {
	op.oc.AddReqStructure(object, options...)
	op.reqExamples = &ExampleObject{
		object: object,
	}
}

func (op *OperationWithExample) AddReqWithExternalRef(ref ExternalRef) {
	op.externalRequest = &ref
}

type ReqOneOfAllOf struct {
	object      interface{}
	Ref         string
	exampleType ExampleType
	objectType  ItemType
	example     interface{}
	contentType string
	AllOfOneOf  AllOfOneOf
}

func (op *OperationWithExample) AddReqOneOfAllOfWithExamples(itemType AllOfOneOf, items []ReqOneOfAllOf) {
	var inlineItems []interface{}
	for i := range items {
		if items[i].objectType == InlineType {
			inlineItems = append(inlineItems, items[i].object)
		}
		items[i].AllOfOneOf = itemType
	}
	if len(inlineItems) != 0 {
		if itemType == AllOff {
			op.oc.AddReqStructure(jsonschema.AllOf(inlineItems...))
		} else {
			op.oc.AddReqStructure(jsonschema.OneOf(inlineItems...))
		}
	}
	op.multipleRequestOneOf = append(op.multipleRequestOneOf, items...)
}

func (op *OperationWithExample) AddReqWithSeparateExample(object interface{}, example interface{}) {
	op.oc.AddReqStructure(object)
	op.reqExamples = &ExampleObject{
		object: example,
	}
}

func (op *OperationWithExample) AddOperation() error {
	o3, ok := op.oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	if len(op.parameters) > 0 {
		o3.Operation().WithParameters(op.parameters...)
	}
	if op.externalRequest != nil {
		addExternalRefToRequest(o3, op.externalRequest)
	}
	err := op.r.AddOperation(op.oc)
	if err != nil {
		return err
	}
	addOneOfAllOfRefsToReq(o3, applicationJSON, op.multipleRequestOneOf)
	if op.reqExamples != nil {
		addReqExample(o3, *op.reqExamples)
	}
	for _, example := range op.respExamples {
		addExample(o3, example)
	}
	addMultipleExamples(o3, op.oneOfExamples)
	for i := range op.externalResponse {
		addExternalRefToResponse(o3, op.externalResponse[i])
	}
	addOneOfAllOfRefsToResponse(o3, op.oneOfAllOfResponseItems)

	for i := range op.binaryFormat {
		addBinaryFormat(o3, op.binaryFormat[i])
	}

	if len(op.respHeaders) > 0 {

		value, ok := o3.Operation().Responses.MapOfResponseOrRefValues["200"]
		if !ok {
			return errors.New("response with given status does not exist")
		}

		newHeaders := value.Response.Headers
		if newHeaders == nil {
			newHeaders = map[string]openapi3.HeaderOrRef{}
		}
		maps.Copy(newHeaders, op.respHeaders)
		o3.Operation().Responses.MapOfResponseOrRefValues["200"].Response.WithHeaders(newHeaders)
	}

	return nil
}

type ExampleObject struct {
	object     interface{}
	httpStatus int
}
type multipleExamplesValues struct {
	object      interface{}
	key         string
	httpStatus  int
	Summary     string
	exampleType ExampleType
	ref         string
	objectType  ItemType
	objectRef   string
	AllOfOneOf  AllOfOneOf
	hasExample  bool
}

func addReqExample(o3 openapi3.OperationExposer, object ExampleObject) {
	///request := o3.Operation().RequestBody
	mediaType := o3.Operation().RequestBody.RequestBody.Content[applicationJSON]
	mediaType.Example = &object.object
	o3.Operation().RequestBody.RequestBody.Content[applicationJSON] = mediaType
}

func addExample(o3 openapi3.OperationExposer, object ExampleObject) {
	code := strconv.Itoa(object.httpStatus)
	_, ok := o3.Operation().Responses.MapOfResponseOrRefValues[code]
	if !ok {
		return
	}
	mediaType := o3.Operation().Responses.MapOfResponseOrRefValues[code].Response.Content[applicationJSON]
	mediaType.Example = &object.object
	o3.Operation().Responses.MapOfResponseOrRefValues[code].Response.Content[applicationJSON] = mediaType
}

func addMultipleExamples(o3 openapi3.OperationExposer, objects []multipleExamplesValues) {
	if len(objects) == 0 {
		return
	}
	code := strconv.Itoa(objects[0].httpStatus)
	_, ok := o3.Operation().Responses.MapOfResponseOrRefValues[code]
	if !ok {
		return
	}
	mediaType := o3.Operation().Responses.MapOfResponseOrRefValues[code].Response.Content[applicationJSON]
	if mediaType.Examples == nil {
		mediaType.Examples = make(map[string]openapi3.ExampleOrRef)
	}
	for i := range objects {
		if objects[i].exampleType == Component {
			mediaType.Examples[objects[i].key] = openapi3.ExampleOrRef{
				ExampleReference: &openapi3.ExampleReference{
					Ref: fmt.Sprintf("#/components/examples/%s", objects[i].ref),
				},
			}
		} else {
			mediaType.Examples[objects[i].key] = openapi3.ExampleOrRef{
				Example: &openapi3.Example{
					Summary: &objects[i].Summary,
					Value:   &objects[i].object,
				},
			}
		}
	}
	o3.Operation().Responses.MapOfResponseOrRefValues[code].Response.Content[applicationJSON] = mediaType
}

type ExternalRef struct {
	Ref             string
	example         interface{}
	externalExample string
	examplType      ExampleType
	componentKey    string
	httpStatusCode  int
	description     string
}

type BinaryFormat struct {
	example     BinaryExample
	httpStatus  int
	description string
}

func addBinaryFormat(o3 openapi3.OperationExposer, format BinaryFormat) {
	code := strconv.Itoa(format.httpStatus)
	//value, ok := o3.Operation().Responses.MapOfResponseOrRefValues[code]
	//if !ok {
	//	return
	//}
	mediaType := openapi3.MediaType{
		Schema: &openapi3.SchemaOrRef{
			Schema: &openapi3.Schema{
				Type:   PointerValue(openapi3.SchemaTypeString),
				Format: PointerValue("binary"),
			},
		},
	}

	if format.example != "" {
		mediaType.Example = valueToInterface(string(format.example))
	}
	response := o3.Operation().Responses.MapOfResponseOrRefValues[code].Response
	if response == nil {
		o3.Operation().Responses.MapOfResponseOrRefValues[code] = openapi3.ResponseOrRef{
			Response: &openapi3.Response{},
		}
	}
	if o3.Operation().Responses.MapOfResponseOrRefValues[code].Response.Content == nil {
		o3.Operation().Responses.MapOfResponseOrRefValues[code].Response.Content = map[string]openapi3.MediaType{}
	}
	if format.description != "" {
		o3.Operation().Responses.MapOfResponseOrRefValues[code].Response.Description = format.description
	}
	o3.Operation().Responses.MapOfResponseOrRefValues[code].Response.Content[applicationOctetStream] = mediaType
}

func addOneOfAllOfRefsToResponse(o3 openapi3.OperationExposer, items []multipleExamplesValues) {
	if len(items) == 0 {
		return
	}
	hasRef := false
	for i := range items {
		if items[i].objectType == ExternalType || items[i].objectType == ComponentType {
			hasRef = true
			break
		}
	}
	if !hasRef {
		return
	}
	itemType := items[0].AllOfOneOf
	code := "200"
	schemaOneOfAllOf := &openapi3.Schema{}
	if itemType == AllOff {
		schemaOneOfAllOf.AllOf = []openapi3.SchemaOrRef{}
	} else {
		schemaOneOfAllOf.OneOf = []openapi3.SchemaOrRef{}
	}
	mediaType := o3.Operation().Responses.MapOfResponseOrRefValues[code].Response.Content[applicationJSON]
	for i := range items {
		n := items[i]
		if n.objectType == InlineType {
			continue
		}
		refIt := openapi3.SchemaOrRef{
			SchemaReference: &openapi3.SchemaReference{Ref: items[i].objectRef},
		}
		if itemType == AllOff {
			mediaType.Schema.Schema.AllOf = append(mediaType.Schema.Schema.AllOf, refIt)
		} else {
			mediaType.Schema.Schema.OneOf = append(mediaType.Schema.Schema.OneOf, refIt)
		}
	}
}

func addOneOfAllOfRefsToReq(o3 openapi3.OperationExposer, contentType string, items []ReqOneOfAllOf) {
	if len(items) == 0 {
		return
	}
	itemType := items[0].AllOfOneOf
	schemaOneOfAllOf := &openapi3.Schema{}
	if itemType == AllOff {
		schemaOneOfAllOf.AllOf = []openapi3.SchemaOrRef{}
	} else {
		schemaOneOfAllOf.OneOf = []openapi3.SchemaOrRef{}
	}
	if o3.Operation().RequestBody == nil {
		o3.Operation().RequestBody = &openapi3.RequestBodyOrRef{
			RequestBody: &openapi3.RequestBody{
				Content: map[string]openapi3.MediaType{},
			},
		}
	}
	if o3.Operation().RequestBody.RequestBody == nil {
		o3.Operation().RequestBody.RequestBody = &openapi3.RequestBody{
			Content: map[string]openapi3.MediaType{},
		}
	}
	if o3.Operation().RequestBody.RequestBody.Content == nil {
		o3.Operation().RequestBody.RequestBody.Content = map[string]openapi3.MediaType{}
	}
	mediaType := o3.Operation().RequestBody.RequestBody.Content[contentType]
	if mediaType.Schema == nil {
		mediaType.Schema = &openapi3.SchemaOrRef{
			Schema: schemaOneOfAllOf,
		}
	}
	if mediaType.Schema.Schema == nil {
		if itemType == OneOf {
			mediaType.Schema.Schema = &openapi3.Schema{
				OneOf: []openapi3.SchemaOrRef{},
			}
		} else {
			mediaType.Schema.Schema = &openapi3.Schema{
				AllOf: []openapi3.SchemaOrRef{},
			}
		}
	}
	if mediaType.Schema.Schema.OneOf == nil && itemType == OneOf {
		mediaType.Schema.Schema.OneOf = []openapi3.SchemaOrRef{}
	}
	if mediaType.Schema.Schema.AllOf == nil && itemType == AllOff {
		mediaType.Schema.Schema.AllOf = []openapi3.SchemaOrRef{}
	}
	for i := range items {
		if items[i].objectType == ExternalType && items[i].contentType == contentType {
			if itemType == OneOf {
				mediaType.Schema.Schema.OneOf = append(mediaType.Schema.Schema.OneOf, openapi3.SchemaOrRef{
					SchemaReference: &openapi3.SchemaReference{Ref: items[i].Ref},
				})
			} else if itemType == AllOff {
				mediaType.Schema.Schema.AllOf = append(mediaType.Schema.Schema.AllOf, openapi3.SchemaOrRef{
					SchemaReference: &openapi3.SchemaReference{Ref: items[i].Ref},
				})
			} else {
				log.Fatalf("failed one off all of")
			}
		}
	}

	o3.Operation().RequestBody.RequestBody.Content[contentType] = mediaType
}

func addExternalRefToResponse(o3 openapi3.OperationExposer, ref ExternalRef) {
	code := strconv.Itoa(ref.httpStatusCode)
	_, ok := o3.Operation().Responses.MapOfResponseOrRefValues[code]
	if !ok {
		// return
	}
	mediaType := openapi3.MediaType{
		Schema: &openapi3.SchemaOrRef{
			Schema: nil,
			SchemaReference: &openapi3.SchemaReference{
				Ref: ref.Ref,
			},
		},
	}
	if ref.examplType == Inline && ref.example != nil {
		mediaType.Example = valueToInterface(mediaType.Example)
	}
	if ref.examplType == Component && ref.componentKey != "" {
		if mediaType.Examples == nil {
			mediaType.Examples = make(map[string]openapi3.ExampleOrRef)
		}
		mediaType.Examples[ref.componentKey] = openapi3.ExampleOrRef{
			ExampleReference: &openapi3.ExampleReference{
				Ref: fmt.Sprintf("#/components/examples/%s", ref.componentKey),
			},
		}
	}
	item := openapi3.ResponseOrRef{
		Response: &openapi3.Response{
			Content: map[string]openapi3.MediaType{applicationJSON: mediaType},
		},
	}
	if ref.description != "" {
		item.Response.Description = ref.description
	}
	o3.Operation().Responses.MapOfResponseOrRefValues[code] = item
}

func addExternalRefToRequest(o3 openapi3.OperationExposer, req *ExternalRef) {
	if req == nil {
		return
	}
	mediaType := openapi3.MediaType{
		Schema: &openapi3.SchemaOrRef{
			SchemaReference: &openapi3.SchemaReference{
				Ref: req.Ref,
			},
		},
	}
	if req.examplType == Component && req.componentKey != "" {
		if mediaType.Examples == nil {
			mediaType.Examples = make(map[string]openapi3.ExampleOrRef)
		}
		mediaType.Examples[req.componentKey] = openapi3.ExampleOrRef{
			ExampleReference: &openapi3.ExampleReference{
				Ref: fmt.Sprintf("#/components/examples/%s", req.componentKey),
			},
		}
	}
	if req.examplType == Inline && req.example != nil {
		mediaType.Example = valueToInterface(req.example)
	}
	o3.Operation().RequestBody = &openapi3.RequestBodyOrRef{
		RequestBodyReference: nil,
		RequestBody: &openapi3.RequestBody{
			Content: map[string]openapi3.MediaType{applicationJSON: mediaType},
		},
	}
}

type ResponseHeader struct {
	Name        string
	Description *string
	Type        *openapi3.SchemaType
}

func PointerValue[T any](value T) *T {
	return &value
}

func valueToInterface(value interface{}) *interface{} {
	return &value
}

type URLVals struct {
	Host     string `json:"Host"`
	BasePath string `json:"BasePath"`
	APIURL   string `json:"ApiURL"`
}

func parseTime(timeStr string) time.Time {
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		fmt.Println("Error parsing time:", err)
		log.Fatal(err)
	}
	return t
}

var Tags []openapi3.Tag

func addTag(name, description string, parameters optionalTagParameters) {
	tag := openapi3.Tag{
		Name:        name,
		Description: PointerValue(description),
	}
	if len(parameters.url) > 0 {
		tag.ExternalDocs = &openapi3.ExternalDocumentation{
			URL: parameters.url,
		}
		if (len(parameters.description)) > 0 {
			tag.ExternalDocs.Description = &parameters.description
		}
	}
	Tags = append(Tags, tag)
}

type optionalTagParameters struct {
	url         string
	description string
}

func (b BinaryExample) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(b))
}

type File struct {
	File multipart.File ` json:"file" formData:"file" required:"true" `
}
