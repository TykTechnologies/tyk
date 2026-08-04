package graphengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/buger/jsonparser"
	"github.com/jensneuse/abstractlogger"

	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/astparser"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/astvisitor"
	postprocessv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/postprocess"
	graphqlv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/introspection"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/operationreport"

	"github.com/TykTechnologies/tyk/apidef"
)

type ContextRetrieveRequestV2Func func(r *http.Request) *graphqlv2.Request
type ContextStoreRequestV2Func func(r *http.Request, gqlRequest *graphqlv2.Request)

type graphqlGoToolsV2 struct{}

func (g graphqlGoToolsV2) parseSchema(schema string) (*graphqlv2.Schema, error) {
	parsed, err := graphqlv2.NewSchemaFromString(schema)
	if err != nil {
		return nil, err
	}

	normalizeResult, err := parsed.Normalize()
	if err != nil {
		return nil, err
	}

	if !normalizeResult.Successful {
		return nil, fmt.Errorf("error normalizing schema: %w", normalizeResult.Errors)
	}

	return parsed, nil
}

func (g graphqlGoToolsV2) handleIntrospection(schema *graphqlv2.Schema) (res *http.Response, hijacked bool, err error) {
	var (
		introspectionData = struct {
			Data introspection.Data `json:"data"`
		}{}
		report operationreport.Report
	)
	gen := introspection.NewGenerator()
	doc, report := astparser.ParseGraphqlDocumentBytes(schema.Document())
	if report.HasErrors() {
		err = report
		return
	}
	gen.Generate(&doc, &report, &introspectionData.Data)

	var buf bytes.Buffer
	err = json.NewEncoder(&buf).Encode(introspectionData)
	if err != nil {
		return
	}

	res = &http.Response{}
	res.Body = io.NopCloser(&buf)
	res.Header = make(http.Header)
	res.StatusCode = 200

	res.Header.Set("Content-Type", "application/json")
	return
}

func (g graphqlGoToolsV2) headerModifier(outreq *http.Request, additionalHeaders http.Header, variableReplacer TykVariableReplacer) postprocessv2.HeaderModifier {
	return func(header http.Header) {
		for key := range additionalHeaders {
			if header.Get(key) == "" {
				header.Set(key, additionalHeaders.Get(key))
			}
		}

		for key := range header {
			val := variableReplacer(outreq, header.Get(key), false)
			header.Set(key, val)
		}
	}
}

func (g graphqlGoToolsV2) returnErrorsFromUpstream(proxyOnlyCtx *GraphQLProxyOnlyContextValues, resultWriter *graphqlv2.EngineResultWriter, seekReadCloser SeekReadCloserFunc) error {
	body, err := seekReadCloser(proxyOnlyCtx.upstreamResponse.Body)
	if body == nil {
		// Response body already read by graphql-go-tools, and it's not re-readable. Quit silently.
		return nil
	} else if err != nil {
		return err
	}

	responseBody, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	// graphql-go-tools error message format: {"errors": [...]}
	// Insert the upstream error into the first error message.
	result, err := jsonparser.Set(resultWriter.Bytes(), responseBody, "errors", "[0]", "extensions")
	if err != nil {
		return err
	}
	resultWriter.Reset()
	_, err = resultWriter.Write(result)
	return err
}

type reverseProxyPreHandlerV2 struct {
	ctxRetrieveGraphQLRequest ContextRetrieveRequestV2Func
	apiDefinition             *apidef.APIDefinition
	httpClient                *http.Client
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
}

func (r *reverseProxyPreHandlerV2) PreHandle(params ReverseProxyParams) (reverseProxyType ReverseProxyType, err error) {
	r.httpClient.Transport = NewGraphQLEngineTransport(
		DetermineGraphQLEngineTransportType(r.apiDefinition),
		params.RoundTripper,
		r.newReusableBodyReadCloser,
		params.HeadersConfig,
	)

	switch {
	case params.IsCORSPreflight:
		return ReverseProxyTypePreFlight, nil
	case params.IsWebSocketUpgrade:
		if params.NeedsEngine {
			return ReverseProxyTypeWebsocketUpgrade, nil
		}
	default:
		gqlRequest := r.ctxRetrieveGraphQLRequest(params.OutRequest)
		if gqlRequest == nil {
			err = errors.New("graphql request is nil")
			return
		}
		gqlRequest.SetHeader(params.OutRequest.Header)

		var isIntrospection bool
		isIntrospection, err = gqlRequest.IsIntrospectionQuery()
		if err != nil {
			return
		}

		if isIntrospection {
			return ReverseProxyTypeIntrospection, nil
		}
		if params.NeedsEngine {
			return ReverseProxyTypeGraphEngine, nil
		}
	}

	return ReverseProxyTypeNone, nil
}

type complexityCheckerV2 struct {
	schema             *graphqlv2.Schema
	logger             abstractlogger.Logger
	ctxRetrieveRequest ContextRetrieveRequestV2Func
}

func (c *complexityCheckerV2) DepthLimitExceeded(r *http.Request, accessDefinition *ComplexityAccessDefinition) ComplexityFailReason {
	if !c.depthLimitEnabled(accessDefinition) {
		return ComplexityFailReasonNone
	}

	gqlRequest := c.ctxRetrieveRequest(r)
	if gqlRequest == nil {
		return ComplexityFailReasonNone
	}

	isIntrospectionQuery, err := gqlRequest.IsIntrospectionQuery()
	if err != nil {
		c.logger.Debug("error while checking for introspection query", abstractlogger.Error(err))
		return ComplexityFailReasonInternalError
	}

	if isIntrospectionQuery {
		return ComplexityFailReasonNone
	}

	complexityRes, err := gqlRequest.CalculateComplexity(graphqlv2.DefaultComplexityCalculator, c.schema)
	if err != nil {
		c.logger.Error("error while calculating complexity of GraphQL request", abstractlogger.Error(err))
		return ComplexityFailReasonInternalError
	}

	if complexityRes.Errors != nil && complexityRes.Errors.Count() > 0 {
		c.logger.Error("error while calculating complexity of GraphQL request", abstractlogger.Error(complexityRes.Errors.ErrorByIndex(0)))
		return ComplexityFailReasonInternalError
	}

	// do per query depth check
	if len(accessDefinition.FieldAccessRights) == 0 {
		if accessDefinition.Limit.MaxQueryDepth > 0 && complexityRes.Depth > accessDefinition.Limit.MaxQueryDepth {
			c.logger.Debug("complexity of the request is higher than the allowed limit", abstractlogger.Int("maxQueryDepth", accessDefinition.Limit.MaxQueryDepth))
			return ComplexityFailReasonDepthLimitExceeded
		}
		return ComplexityFailReasonNone
	}

	// do per query field depth check
	for _, fieldComplexityRes := range complexityRes.PerRootField {
		var (
			fieldAccessDefinition ComplexityFieldAccessDefinition
			hasPerFieldLimits     bool
		)

		for _, fieldAccessRight := range accessDefinition.FieldAccessRights {
			if fieldComplexityRes.TypeName != fieldAccessRight.TypeName {
				continue
			}
			if fieldComplexityRes.FieldName != fieldAccessRight.FieldName {
				continue
			}

			fieldAccessDefinition = fieldAccessRight
			hasPerFieldLimits = true
			break
		}

		if hasPerFieldLimits {
			if greaterThanIntConsideringUnlimited(fieldComplexityRes.Depth, fieldAccessDefinition.Limits.MaxQueryDepth) {
				c.logger.Debug(
					"depth of the root field is higher than the allowed field limit",
					abstractlogger.Int("depth", fieldComplexityRes.Depth),
					abstractlogger.String("rootField", fmt.Sprintf("%s.%s", fieldAccessDefinition.TypeName, fieldAccessDefinition.FieldName)),
					abstractlogger.Int("maxQueryDepth", fieldAccessDefinition.Limits.MaxQueryDepth),
				)

				return ComplexityFailReasonDepthLimitExceeded
			}
			continue
		}

		// favour global limit for query field
		// have to increase resulting field depth by 1 to get a global depth
		queryDepth := fieldComplexityRes.Depth + 1
		if greaterThanIntConsideringUnlimited(queryDepth, accessDefinition.Limit.MaxQueryDepth) {
			c.logger.Debug(
				"depth of the root field is higher than the allowed global limit",
				abstractlogger.Int("depth", queryDepth),
				abstractlogger.String("rootField", fmt.Sprintf("%s.%s", fieldComplexityRes.TypeName, fieldComplexityRes.FieldName)),
				abstractlogger.Int("maxQueryDepth", accessDefinition.Limit.MaxQueryDepth),
			)

			return ComplexityFailReasonDepthLimitExceeded
		}
	}
	return ComplexityFailReasonNone

}

func (c *complexityCheckerV2) depthLimitEnabled(accessDefinition *ComplexityAccessDefinition) bool {
	if accessDefinition == nil {
		return false
	}

	if accessDefinition.Limit.MaxQueryDepth == -1 && len(accessDefinition.FieldAccessRights) == 0 {
		return false
	}

	return accessDefinition.Limit.MaxQueryDepth != -1 || len(accessDefinition.FieldAccessRights) != 0
}

type granularAccessCheckerV2 struct {
	logger                    abstractlogger.Logger
	schema                    *graphqlv2.Schema
	ctxRetrieveGraphQLRequest ContextRetrieveRequestV2Func
}

func (g *granularAccessCheckerV2) CheckGraphQLRequestFieldAllowance(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) GraphQLGranularAccessResult {
	gqlRequest := g.ctxRetrieveGraphQLRequest(r)
	if gqlRequest == nil {
		return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonNone}
	}

	isIntrospection, err := gqlRequest.IsIntrospectionQueryStrict()
	if err != nil {
		return GraphQLGranularAccessResult{
			FailReason:  GranularAccessFailReasonInternalError,
			InternalErr: err,
		}
	}
	if isIntrospection {
		if accessDefinition.DisableIntrospection {
			return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonIntrospectionDisabled}
		}

		// See TT-11260
		//
		// Introspection should be possible when Disable Introspection is turned off in policy settings,
		// regardless of Allow List or Block List settings.
		//
		// Agreed solution: if Disable Introspection is turned off, then the Allow or Block list settings
		// should be ignored, but only for the introspection query.
		return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonNone}
	}

	if len(accessDefinition.AllowedTypes) != 0 {
		fieldRestrictionList := graphqlv2.FieldRestrictionList{
			Kind:  graphqlv2.AllowList,
			Types: g.convertGranularAccessTypeToGraphQLType(accessDefinition.AllowedTypes),
		}
		return g.validateFieldRestrictions(gqlRequest, fieldRestrictionList, g.schema)
	}

	if len(accessDefinition.RestrictedTypes) != 0 {
		fieldRestrictionList := graphqlv2.FieldRestrictionList{
			Kind:  graphqlv2.BlockList,
			Types: g.convertGranularAccessTypeToGraphQLType(accessDefinition.RestrictedTypes),
		}
		return g.validateFieldRestrictions(gqlRequest, fieldRestrictionList, g.schema)
	}

	// There are no restricted types. Every field is allowed access.
	return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonNone}
}

func (g *granularAccessCheckerV2) convertGranularAccessTypeToGraphQLType(accessTypes []GranularAccessType) []graphqlv2.Type {
	var types []graphqlv2.Type
	for _, accessType := range accessTypes {
		types = append(types, graphqlv2.Type{
			Name:   accessType.Name,
			Fields: accessType.Fields,
		})
	}
	return types
}

func (g *granularAccessCheckerV2) validateFieldRestrictions(gqlRequest *graphqlv2.Request, fieldRestrictionList graphqlv2.FieldRestrictionList, schema *graphqlv2.Schema) GraphQLGranularAccessResult {
	result, err := gqlRequest.ValidateFieldRestrictions(schema, fieldRestrictionList, &TykFieldsValidatorV2{
		Variables: gqlRequest.Variables,
	})
	if err != nil {
		return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonInternalError, InternalErr: err}
	}

	if !result.Valid || (result.Errors != nil && result.Errors.Count() > 0) {
		return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonValidationError, ValidationError: result.Errors, writeErrorResponse: g.writeErrorResponse}
	}
	return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonNone}
}

type TykFieldsValidatorV2 struct {
	Variables []byte
}

type inputFieldsVisitorV2 struct {
	walker            *astvisitor.Walker
	operation         *ast.Document
	definition        *ast.Document
	variables         []byte
	data              graphqlv2.RequestTypes
	currentParentType ast.Node
}

func (v *inputFieldsVisitorV2) EnterField(ref int) {
	v.currentParentType = v.walker.EnclosingTypeDefinition
}

func (v *inputFieldsVisitorV2) EnterArgument(ref int) {
	argName := v.operation.ArgumentNameString(ref)
	val := v.operation.ArgumentValue(ref)

	if len(v.walker.Ancestors) == 0 {
		return
	}
	parentFieldNode := v.walker.Ancestors[len(v.walker.Ancestors)-1]
	if parentFieldNode.Kind != ast.NodeKindField {
		return
	}
	fieldName := v.operation.FieldNameString(parentFieldNode.Ref)

	parentType := v.currentParentType
	fieldDefRef, exists := v.getFieldDefinition(parentType, fieldName)
	if !exists {
		return
	}

	var argTypeName string
	for _, argDefRef := range v.definition.FieldDefinitionArgumentsDefinitions(fieldDefRef) {
		if v.definition.InputValueDefinitionNameString(argDefRef) == argName {
			typeRef := v.definition.InputValueDefinitionType(argDefRef)
			argTypeName = v.definition.ResolveTypeNameString(typeRef)
			break
		}
	}

	if argTypeName == "" {
		return
	}

	if val.Kind == ast.ValueKindObject {
		v.walkInlineObjectValue(val.Ref, argTypeName)
	} else if val.Kind == ast.ValueKindVariable {
		varName := v.operation.VariableValueNameString(val.Ref)
		varType, ok := v.getVariableTypeName(varName)
		if ok {
			varValue, _, _, err := jsonparser.Get(v.variables, varName)
			if err == nil {
				v.walkJSONValue(varValue, varType)
			}
		}
	}
}

func (v *inputFieldsVisitorV2) getFieldDefinition(parentType ast.Node, fieldName string) (int, bool) {
	switch parentType.Kind {
	case ast.NodeKindObjectTypeDefinition:
		for _, fieldDefRef := range v.definition.ObjectTypeDefinitions[parentType.Ref].FieldsDefinition.Refs {
			if v.definition.FieldDefinitionNameString(fieldDefRef) == fieldName {
				return fieldDefRef, true
			}
		}
	case ast.NodeKindInterfaceTypeDefinition:
		for _, fieldDefRef := range v.definition.InterfaceTypeDefinitions[parentType.Ref].FieldsDefinition.Refs {
			if v.definition.FieldDefinitionNameString(fieldDefRef) == fieldName {
				return fieldDefRef, true
			}
		}
	}
	return 0, false
}

func (v *inputFieldsVisitorV2) getVariableTypeName(varName string) (string, bool) {
	for _, varDef := range v.operation.VariableDefinitions {
		name := v.operation.VariableValueNameString(varDef.VariableValue.Ref)
		if name == varName {
			typeRef := varDef.Type
			return v.operation.ResolveTypeNameString(typeRef), true
		}
	}
	return "", false
}

func (v *inputFieldsVisitorV2) walkJSONValue(value []byte, typeName string) {
	node, exists := v.definition.Index.FirstNodeByNameStr(typeName)
	if !exists || node.Kind != ast.NodeKindInputObjectTypeDefinition {
		return
	}

	_ = jsonparser.ObjectEach(value, func(key []byte, val []byte, dataType jsonparser.ValueType, offset int) error {
		fieldName := string(key)
		t, ok := v.data[typeName]
		if !ok {
			t = make(graphqlv2.RequestFields)
		}
		t[fieldName] = struct{}{}
		v.data[typeName] = t

		fieldRef := v.definition.InputObjectTypeDefinitionInputValueDefinitionByName(node.Ref, key)
		if fieldRef != -1 {
			fieldTypeRef := v.definition.InputValueDefinitionType(fieldRef)
			fieldTypeName := v.definition.ResolveTypeNameString(fieldTypeRef)

			if dataType == jsonparser.Object {
				v.walkJSONValue(val, fieldTypeName)
			} else if dataType == jsonparser.Array {
				_, _ = jsonparser.ArrayEach(val, func(arrVal []byte, arrDataType jsonparser.ValueType, arrOffset int, arrErr error) {
					if arrDataType == jsonparser.Object {
						v.walkJSONValue(arrVal, fieldTypeName)
					}
				})
			}
		}
		return nil
	})
}

func (v *inputFieldsVisitorV2) walkInlineObjectValue(ref int, typeName string) {
	node, exists := v.definition.Index.FirstNodeByNameStr(typeName)
	if !exists || node.Kind != ast.NodeKindInputObjectTypeDefinition {
		return
	}

	objVal := v.operation.ObjectValues[ref]
	for _, fieldRef := range objVal.Refs {
		field := v.operation.ObjectFields[fieldRef]
		fieldName := v.operation.ObjectFieldNameString(fieldRef)

		t, ok := v.data[typeName]
		if !ok {
			t = make(graphqlv2.RequestFields)
		}
		t[fieldName] = struct{}{}
		v.data[typeName] = t

		schemaFieldRef := v.definition.InputObjectTypeDefinitionInputValueDefinitionByName(node.Ref, []byte(fieldName))
		if schemaFieldRef != -1 {
			fieldTypeRef := v.definition.InputValueDefinitionType(schemaFieldRef)
			fieldTypeName := v.definition.ResolveTypeNameString(fieldTypeRef)

			if field.Value.Kind == ast.ValueKindObject {
				v.walkInlineObjectValue(field.Value.Ref, fieldTypeName)
			} else if field.Value.Kind == ast.ValueKindList {
				v.walkInlineListValue(field.Value.Ref, fieldTypeName)
			} else if field.Value.Kind == ast.ValueKindVariable {
				varName := v.operation.VariableValueNameString(field.Value.Ref)
				varValue, _, _, err := jsonparser.Get(v.variables, varName)
				if err == nil {
					v.walkJSONValue(varValue, fieldTypeName)
				}
			}
		}
	}
}

func (v *inputFieldsVisitorV2) walkInlineListValue(ref int, typeName string) {
	listVal := v.operation.ListValues[ref]
	for _, valRef := range listVal.Refs {
		val := v.operation.Values[valRef]
		if val.Kind == ast.ValueKindObject {
			v.walkInlineObjectValue(val.Ref, typeName)
		} else if val.Kind == ast.ValueKindList {
			v.walkInlineListValue(val.Ref, typeName)
		} else if val.Kind == ast.ValueKindVariable {
			varName := v.operation.VariableValueNameString(val.Ref)
			varValue, _, _, err := jsonparser.Get(v.variables, varName)
			if err == nil {
				v.walkJSONValue(varValue, typeName)
			}
		}
	}
}

func (t *TykFieldsValidatorV2) ValidateByFieldList(request *graphqlv2.Request, schema *graphqlv2.Schema, restrictionList graphqlv2.FieldRestrictionList) (graphqlv2.RequestFieldsValidationResult, error) {
	report := operationreport.Report{}
	if len(restrictionList.Types) == 0 {
		return graphqlv2.RequestFieldsValidationResult{Valid: true}, nil
	}

	requestedTypes := make(graphqlv2.RequestTypes)
	graphqlv2.NewExtractor().ExtractFieldsFromRequest(request, schema, &report, requestedTypes)
	if report.HasErrors() {
		return graphqlv2.RequestFieldsValidationResult{Valid: false, Errors: graphqlv2.RequestErrorsFromOperationReport(report)}, nil
	}

	reqDoc, reqReport := astparser.ParseGraphqlDocumentString(request.Query)
	if reqReport.HasErrors() {
		return graphqlv2.RequestFieldsValidationResult{Valid: false, Errors: graphqlv2.RequestErrorsFromOperationReport(reqReport)}, nil
	}

	schemaDoc, schemaReport := astparser.ParseGraphqlDocumentBytes(schema.Document())
	if schemaReport.HasErrors() {
		return graphqlv2.RequestFieldsValidationResult{Valid: false, Errors: graphqlv2.RequestErrorsFromOperationReport(schemaReport)}, nil
	}

	walker := astvisitor.NewWalker(48)
	visitor := inputFieldsVisitorV2{
		walker:     &walker,
		operation:  &reqDoc,
		definition: &schemaDoc,
		variables:  t.Variables,
		data:       requestedTypes,
	}

	walker.RegisterEnterFieldVisitor(&visitor)
	walker.RegisterEnterArgumentVisitor(&visitor)

	walker.Walk(&reqDoc, &schemaDoc, &report)
	if report.HasErrors() {
		return graphqlv2.RequestFieldsValidationResult{Valid: false, Errors: graphqlv2.RequestErrorsFromOperationReport(report)}, nil
	}

	if fieldRestrictionListKindV2(restrictionList.Kind) == blockListV2 {
		return checkForBlockedFieldsV2(restrictionList, requestedTypes)
	}

	return checkForAllowedFieldsV2(restrictionList, requestedTypes)
}

type fieldRestrictionListKindV2 int

const (
	allowListV2 fieldRestrictionListKindV2 = iota
	blockListV2
)

func checkForBlockedFieldsV2(restrictionList graphqlv2.FieldRestrictionList, requestTypes graphqlv2.RequestTypes) (graphqlv2.RequestFieldsValidationResult, error) {
	restrictedFieldsLookupMap := make(map[string]map[string]bool)
	for _, restrictedType := range restrictionList.Types {
		restrictedFieldsLookupMap[restrictedType.Name] = make(map[string]bool)
		for _, restrictedField := range restrictedType.Fields {
			restrictedFieldsLookupMap[restrictedType.Name][restrictedField] = true
		}
	}

	for requestType, requestFields := range requestTypes {
		for requestField := range requestFields {
			if _, ok := restrictedFieldsLookupMap[requestType]["*"]; ok {
				return graphqlv2.RequestFieldsValidationResult{
					Valid: false,
					Errors: graphqlv2.RequestErrors{
						graphqlv2.RequestError{
							Message: fmt.Sprintf("all fields of %s type are restricted", requestType),
						},
					},
				}, nil
			}

			isRestrictedType := restrictedFieldsLookupMap[requestType][requestField]
			if isRestrictedType {
				return graphqlv2.RequestFieldsValidationResult{
					Valid: false,
					Errors: graphqlv2.RequestErrors{
						graphqlv2.RequestError{
							Message: fmt.Sprintf("field: %s is restricted on type: %s", requestField, requestType),
						},
					},
				}, nil
			}
		}
	}

	return graphqlv2.RequestFieldsValidationResult{Valid: true}, nil
}

func checkForAllowedFieldsV2(restrictionList graphqlv2.FieldRestrictionList, requestTypes graphqlv2.RequestTypes) (graphqlv2.RequestFieldsValidationResult, error) {
	allowedFieldsLookupMap := make(map[string]map[string]bool)
	for _, allowedType := range restrictionList.Types {
		allowedFieldsLookupMap[allowedType.Name] = make(map[string]bool)
		for _, allowedField := range allowedType.Fields {
			allowedFieldsLookupMap[allowedType.Name][allowedField] = true
		}
	}

	for requestType, requestFields := range requestTypes {
		if _, ok := allowedFieldsLookupMap[requestType]["*"]; ok {
			continue
		}

		for requestField := range requestFields {
			isAllowedField := allowedFieldsLookupMap[requestType][requestField]
			if !isAllowedField {
				return graphqlv2.RequestFieldsValidationResult{
					Valid: false,
					Errors: graphqlv2.RequestErrors{
						graphqlv2.RequestError{
							Message: fmt.Sprintf("field: %s is restricted on type: %s", requestField, requestType),
						},
					},
				}, nil
			}
		}
	}

	return graphqlv2.RequestFieldsValidationResult{Valid: true}, nil
}

func (g *granularAccessCheckerV2) writeErrorResponse(w io.Writer, providedErr error) (n int, err error) {
	return graphqlv2.RequestErrorsFromError(providedErr).WriteResponse(w)
}
