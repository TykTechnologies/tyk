package graphengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/TykTechnologies/graphql-go-tools/pkg/execution/datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/jensneuse/abstractlogger"

	"github.com/TykTechnologies/tyk/apidef"
	internalgraphql "github.com/TykTechnologies/tyk/internal/graphql"
)

const (
	HTTPJSONDataSource   = "HTTPJSONDataSource"
	GraphQLDataSource    = "GraphQLDataSource"
	SchemaDataSource     = "SchemaDataSource"
	TykRESTDataSource    = "TykRESTDataSource"
	TykGraphQLDataSource = "TykGraphQLDataSource"
)

type ContextRetrieveRequestV1Func func(r *http.Request) *graphql.Request
type ContextStoreRequestV1Func func(r *http.Request, gqlRequest *graphql.Request)

type createExecutionEngineV1Params struct {
	logger              abstractlogger.Logger
	apiDef              *apidef.APIDefinition
	schema              *graphql.Schema
	httpClient          *http.Client
	preSendHttpHook     datasource.PreSendHttpHook
	postReceiveHttpHook datasource.PostReceiveHttpHook
}

// graphqlGoToolsV1 is a stateless utility struct that abstracts graphql-go-tools/v1 functionality.
type graphqlGoToolsV1 struct{}

func (g graphqlGoToolsV1) parseSchema(schema string) (*graphql.Schema, error) {
	parsedSchema, err := graphql.NewSchemaFromString(schema)
	if err != nil {
		return nil, err
	}

	normalizationResult, err := parsedSchema.Normalize()
	if err != nil {
		return nil, err
	}

	if !normalizationResult.Successful {
		return nil, fmt.Errorf("schema normalization was not successful. Reason: %w", normalizationResult.Errors)
	}

	return parsedSchema, nil
}

func (g graphqlGoToolsV1) createExecutionEngine(params createExecutionEngineV1Params) (*graphql.ExecutionEngine, error) {
	typeFieldConfigurations := params.apiDef.GraphQL.TypeFieldConfigurations
	if params.schema.HasQueryType() {
		typeFieldConfigurations = append(typeFieldConfigurations, datasource.TypeFieldConfiguration{
			TypeName:  params.schema.QueryTypeName(),
			FieldName: "__schema",
			DataSource: datasource.SourceConfig{
				Name: SchemaDataSource,
				Config: func() json.RawMessage {
					res, _ := json.Marshal(datasource.SchemaDataSourcePlannerConfig{})
					return res
				}(),
			},
		})
	}

	plannerConfig := datasource.PlannerConfiguration{
		TypeFieldConfigurations: typeFieldConfigurations,
	}

	engine, err := graphql.NewExecutionEngine(params.logger, params.schema, plannerConfig)
	if err != nil {
		//g.logger.Error("GraphQL execution engine couldn't be created", abstractlogger.Error(err))
		params.logger.Error("graphql execution engine couldn't be created", abstractlogger.Error(err))
		return nil, err
	}

	hooks := &datasource.Hooks{
		PreSendHttpHook:     params.preSendHttpHook,
		PostReceiveHttpHook: params.postReceiveHttpHook,
	}

	httpJSONOptions := graphql.DataSourceHttpJsonOptions{
		HttpClient:         params.httpClient,
		WhitelistedSchemes: []string{"tyk"},
		Hooks:              hooks,
	}

	graphQLOptions := graphql.DataSourceGraphqlOptions{
		HttpClient:         params.httpClient,
		WhitelistedSchemes: []string{"tyk"},
		Hooks:              hooks,
	}

	errMsgFormat := "%s couldn't be added"

	err = engine.AddHttpJsonDataSourceWithOptions(HTTPJSONDataSource, httpJSONOptions)
	if err != nil {
		//g.logger.Error(fmt.Sprintf(errMsgFormat, HTTPJSONDataSource), abstractlogger.Error(err))
		params.logger.Error(fmt.Sprintf(errMsgFormat, HTTPJSONDataSource), abstractlogger.Error(err))
	}

	err = engine.AddHttpJsonDataSourceWithOptions(TykRESTDataSource, httpJSONOptions)
	if err != nil {
		//g.logger.Error(fmt.Sprintf(errMsgFormat, HTTPJSONDataSource), abstractlogger.Error(err))
		params.logger.Error(fmt.Sprintf(errMsgFormat, HTTPJSONDataSource), abstractlogger.Error(err))
	}

	err = engine.AddGraphqlDataSourceWithOptions(GraphQLDataSource, graphQLOptions)
	if err != nil {
		//g.logger.Error(fmt.Sprintf(errMsgFormat, GraphQLDataSource), abstractlogger.Error(err))
		params.logger.Error(fmt.Sprintf(errMsgFormat, GraphQLDataSource), abstractlogger.Error(err))
	}

	err = engine.AddGraphqlDataSourceWithOptions(TykGraphQLDataSource, graphQLOptions)
	if err != nil {
		//g.logger.Error(fmt.Sprintf(errMsgFormat, GraphQLDataSource), abstractlogger.Error(err))
		params.logger.Error(fmt.Sprintf(errMsgFormat, GraphQLDataSource), abstractlogger.Error(err))
	}

	err = engine.AddDataSource(SchemaDataSource, datasource.SchemaDataSourcePlannerFactoryFactory{})
	if err != nil {
		//g.logger.Error(fmt.Sprintf(errMsgFormat, SchemaDataSource), abstractlogger.Error(err))
		params.logger.Error(fmt.Sprintf(errMsgFormat, SchemaDataSource), abstractlogger.Error(err))
	}

	//m.Spec.GraphQLExecutor.Client = httpJSONOptions.HttpClient

	return engine, err
}

type graphqlRequestProcessorV1 struct {
	logger             abstractlogger.Logger
	schema             *graphql.Schema
	ctxRetrieveRequest ContextRetrieveRequestV1Func
}

func (g *graphqlRequestProcessorV1) ProcessRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) (error, int) {
	if r == nil {
		g.logger.Error("request is nil")
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	gqlRequest := g.ctxRetrieveRequest(r)
	normalizationResult, err := gqlRequest.Normalize(g.schema)
	if err != nil {
		//m.Logger().Errorf("Error while normalizing GraphQL request: '%s'", err)
		g.logger.Error("error while normalizing GraphQL request", abstractlogger.Error(err))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if normalizationResult.Errors != nil && normalizationResult.Errors.Count() > 0 {
		return writeGraphQLError(g.logger, w, normalizationResult.Errors)
	}

	validationResult, err := gqlRequest.ValidateForSchema(g.schema)
	if err != nil {
		//m.Logger().Errorf("Error while validating GraphQL request: '%s'", err)
		g.logger.Error("error while validating GraphQL request", abstractlogger.Error(err))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if validationResult.Errors != nil && validationResult.Errors.Count() > 0 {
		return writeGraphQLError(g.logger, w, validationResult.Errors)
	}

	inputValidationResult, err := gqlRequest.ValidateInput(g.schema)
	if err != nil {
		//m.Logger().Errorf("Error while validating variables for request: %v", err)
		g.logger.Error("error while validating variables for request", abstractlogger.Error(err))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}
	if inputValidationResult.Errors != nil && inputValidationResult.Errors.Count() > 0 {
		return writeGraphQLError(g.logger, w, inputValidationResult.Errors)
	}
	return nil, http.StatusOK
}

type graphqlRequestProcessorWithOtelV1 struct {
	logger             abstractlogger.Logger
	schema             *graphql.Schema
	otelExecutor       internalgraphql.TykOtelExecutorI
	ctxRetrieveRequest ContextRetrieveRequestV1Func
}

func (g *graphqlRequestProcessorWithOtelV1) ProcessRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) (error, int) {
	if r == nil {
		g.logger.Error("request is nil")
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	g.otelExecutor.SetContext(ctx)
	gqlRequest := g.ctxRetrieveRequest(r)

	// normalization
	err := g.otelExecutor.Normalize(gqlRequest)
	if err != nil {
		//m.Logger().Errorf("Error while normalizing GraphqlRequest: %v", err)
		g.logger.Error("error while normalizing GraphqlRequest", abstractlogger.Error(err))
		var reqErr graphql.RequestErrors
		if errors.As(err, &reqErr) {
			return writeGraphQLError(g.logger, w, reqErr)
		}
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	// validation
	err = g.otelExecutor.ValidateForSchema(gqlRequest)
	if err != nil {
		//m.Logger().Errorf("Error while validating GraphQL request: '%s'", err)
		g.logger.Error("error while validating GraphQL request", abstractlogger.Error(err))
		var reqErr graphql.RequestErrors
		if errors.As(err, &reqErr) {
			return writeGraphQLError(g.logger, w, reqErr)
		}
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	// input validation
	err = g.otelExecutor.InputValidation(gqlRequest)
	if err != nil {
		//m.Logger().Errorf("Error while validating variables for request: %v", err)
		g.logger.Error("error while validating variables for request", abstractlogger.Error(err))
		var reqErr graphql.RequestErrors
		if errors.As(err, &reqErr) {
			return writeGraphQLError(g.logger, w, reqErr)
		}
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}
	return nil, http.StatusOK
}

type complexityCheckerV1 struct {
	logger             *abstractlogger.LogrusLogger
	schema             *graphql.Schema
	ctxRetrieveRequest ContextRetrieveRequestV1Func
}

func (c *complexityCheckerV1) DepthLimitExceeded(r *http.Request, accessDefinition *ComplexityAccessDefinition) ComplexityFailReason {
	/*if !c.DepthLimitEnabled(accessDef) {
		return ComplexityFailReasonNone
	}*/

	gqlRequest := c.ctxRetrieveRequest(r)

	isIntrospectionQuery, err := gqlRequest.IsIntrospectionQuery()
	if err != nil {
		//c.logger.Debugf("Error while checking for introspection query: '%s'", err.Error())
		c.logger.Debug("error while checking for introspection query", abstractlogger.Error(err))
		return ComplexityFailReasonInternalError
	}

	if isIntrospectionQuery {
		return ComplexityFailReasonNone
	}

	complexityRes, err := gqlRequest.CalculateComplexity(graphql.DefaultComplexityCalculator, c.schema)
	if err != nil {
		//c.logger.Errorf("Error while calculating complexity of GraphQL request: '%s'", err)
		c.logger.Error("error while calculating complexity of GraphQL request", abstractlogger.Error(err))
		return ComplexityFailReasonInternalError
	}

	if complexityRes.Errors != nil && complexityRes.Errors.Count() > 0 {
		//c.logger.Errorf("Error while calculating complexity of GraphQL request: '%s'", complexityRes.Errors.ErrorByIndex(0))
		c.logger.Error("error while calculating complexity of GraphQL request", abstractlogger.Error(complexityRes.Errors.ErrorByIndex(0)))
		return ComplexityFailReasonInternalError
	}

	// do per query depth check
	if len(accessDefinition.FieldAccessRights) == 0 {
		if complexityRes.Depth > accessDefinition.Limit.MaxQueryDepth {
			//c.logger.Debugf("Complexity of the request is higher than the allowed limit '%d'", accessDefinition.Limit.MaxQueryDepth)
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
				//c.logger.Debugf("Depth '%d' of the root field: %s.%s is higher than the allowed field limit '%d'",
				//	fieldComplexityRes.Depth, fieldAccessDefinition.TypeName, fieldAccessDefinition.FieldName, fieldAccessDefinition.Limits.MaxQueryDepth)
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
			//c.logger.Debugf("Depth '%d' of the root field: %s.%s is higher than the allowed global limit '%d'",
			//	queryDepth, fieldComplexityRes.TypeName, fieldComplexityRes.FieldName, accessDefinition.Limit.MaxQueryDepth)

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

type granularAccessCheckerV1 struct {
	logger                    *abstractlogger.LogrusLogger
	schema                    *graphql.Schema
	ctxRetrieveGraphQLRequest ContextRetrieveRequestV1Func
}

func (g *granularAccessCheckerV1) CheckGraphQLRequestFieldAllowance(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) GraphQLGranularAccessResult {
	gqlRequest := g.ctxRetrieveGraphQLRequest(r)

	if len(accessDefinition.AllowedTypes) != 0 {
		fieldRestrictionList := graphql.FieldRestrictionList{
			Kind:  graphql.AllowList,
			Types: g.convertGranularAccessTypeToGraphQLType(accessDefinition.AllowedTypes),
		}
		return g.validateFieldRestrictions(gqlRequest, fieldRestrictionList, g.schema)
	}

	if len(accessDefinition.RestrictedTypes) != 0 {
		fieldRestrictionList := graphql.FieldRestrictionList{
			Kind:  graphql.BlockList,
			Types: g.convertGranularAccessTypeToGraphQLType(accessDefinition.RestrictedTypes),
		}
		return g.validateFieldRestrictions(gqlRequest, fieldRestrictionList, g.schema)
	}

	// There are no restricted types. Every field is allowed access.
	return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonNone}
}

func (g *granularAccessCheckerV1) validateFieldRestrictions(gqlRequest *graphql.Request, fieldRestrictionList graphql.FieldRestrictionList, schema *graphql.Schema) GraphQLGranularAccessResult {
	result, err := gqlRequest.ValidateFieldRestrictions(schema, fieldRestrictionList, graphql.DefaultFieldsValidator{})
	if err != nil {
		return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonInternalError, InternalErr: err}
	}

	if !result.Valid || (result.Errors != nil && result.Errors.Count() > 0) {
		return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonValidationError, ValidationError: result.Errors, writeErrorResponse: g.writeErrorResponse}
	}
	return GraphQLGranularAccessResult{FailReason: GranularAccessFailReasonNone}
}

func (g *granularAccessCheckerV1) convertGranularAccessTypeToGraphQLType(accessTypes []GranularAccessType) []graphql.Type {
	var types []graphql.Type
	for _, accessType := range accessTypes {
		types = append(types, graphql.Type{
			Name:   accessType.Name,
			Fields: accessType.Fields,
		})
	}
	return types
}

func (g *granularAccessCheckerV1) writeErrorResponse(w io.Writer, providedErr error) (n int, err error) {
	return graphql.RequestErrorsFromError(providedErr).WriteResponse(w)
}

type reverseProxyPreHandlerV1 struct {
	ctxRetrieveGraphQLRequest ContextRetrieveRequestV1Func
	apiDefinition             *apidef.APIDefinition
	httpClient                *http.Client
	transportModifier         TransportModifier
}

func (r *reverseProxyPreHandlerV1) PreHandle(params ReverseProxyParams) (reverseProxyType ReverseProxyType, err error) {
	r.httpClient.Transport = r.transportModifier(params.RoundTripper, r.apiDefinition)
	gqlRequest := r.ctxRetrieveGraphQLRequest(params.OutRequest)
	if gqlRequest == nil {
		err = errors.New("graphql request is nil")
		return
	}

	switch {
	case params.IsCORSPreflight:
		if params.NeedsEngine {
			err = errors.New("options passthrough not allowed")
			return
		}
	case params.IsWebSocketUpgrade:
		if params.NeedsEngine {
			return ReverseProxyTypeWebsocketUpgrade, nil
		}
	default:
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
