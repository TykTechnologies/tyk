package graphengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/jensneuse/abstractlogger"

	"github.com/buger/jsonparser"

	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/astparser"
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
	result, err := gqlRequest.ValidateFieldRestrictions(schema, fieldRestrictionList, graphqlv2.DefaultFieldsValidator{})
	if err != nil {
		return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonInternalError, InternalErr: err}
	}

	if !result.Valid || (result.Errors != nil && result.Errors.Count() > 0) {
		return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonValidationError, ValidationError: result.Errors, writeErrorResponse: g.writeErrorResponse}
	}
	return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonNone}
}

func (g *granularAccessCheckerV2) writeErrorResponse(w io.Writer, providedErr error) (n int, err error) {
	return graphqlv2.RequestErrorsFromError(providedErr).WriteResponse(w)
}
