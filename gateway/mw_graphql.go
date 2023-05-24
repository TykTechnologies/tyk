package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/pkg/execution/datasource"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/adapter"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/user"

	gql "github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
)

const (
	HTTPJSONDataSource   = "HTTPJSONDataSource"
	GraphQLDataSource    = "GraphQLDataSource"
	SchemaDataSource     = "SchemaDataSource"
	TykRESTDataSource    = "TykRESTDataSource"
	TykGraphQLDataSource = "TykGraphQLDataSource"
)

const (
	GraphQLWebSocketProtocol = "graphql-ws"
)

var (
	ProxyingRequestFailedErr     = errors.New("there was a problem proxying the request")
	GraphQLDepthLimitExceededErr = errors.New("depth limit exceeded")
)

type GraphQLMiddleware struct {
	BaseMiddleware
}

func (m *GraphQLMiddleware) Name() string {
	return "GraphQLMiddleware"
}

func (m *GraphQLMiddleware) EnabledForSpec() bool {
	return m.Spec.GraphQL.Enabled
}

func (m *GraphQLMiddleware) Init() {
	schema, err := gql.NewSchemaFromString(m.Spec.GraphQL.Schema)
	if err != nil {
		log.Errorf("Error while creating schema from API definition: %v", err)
		return
	}

	normalizationResult, err := schema.Normalize()
	if err != nil {
		log.Errorf("Error while normalizing schema from API definition: %v", err)
	}

	if !normalizationResult.Successful {
		log.Errorf("Schema normalization was not successful. Reason: %v", normalizationResult.Errors)
	}

	m.Spec.GraphQLExecutor.Schema = schema

	if needsGraphQLExecutionEngine(m.Spec) {
		absLogger := abstractlogger.NewLogrusLogger(log, absLoggerLevel(log.Level))
		m.Spec.GraphQLExecutor.Client = &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsClientConfig(m.Spec)},
		}
		m.Spec.GraphQLExecutor.StreamingClient = &http.Client{
			Timeout:   0,
			Transport: &http.Transport{TLSClientConfig: tlsClientConfig(m.Spec)},
		}

		if m.Spec.GraphQL.Version == apidef.GraphQLConfigVersionNone || m.Spec.GraphQL.Version == apidef.GraphQLConfigVersion1 {
			m.initGraphQLEngineV1(absLogger)
		} else if m.Spec.GraphQL.Version == apidef.GraphQLConfigVersion2 {
			m.initGraphQLEngineV2(absLogger)
		} else {
			log.Errorf("Could not init GraphQL middleware: invalid config version provided: %s", m.Spec.GraphQL.Version)
		}
	}
}

func (m *GraphQLMiddleware) initGraphQLEngineV1(logger *abstractlogger.LogrusLogger) {
	typeFieldConfigurations := m.Spec.GraphQL.TypeFieldConfigurations
	if m.Spec.GraphQLExecutor.Schema.HasQueryType() {
		typeFieldConfigurations = append(typeFieldConfigurations, datasource.TypeFieldConfiguration{
			TypeName:  m.Spec.GraphQLExecutor.Schema.QueryTypeName(),
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

	engine, err := gql.NewExecutionEngine(logger, m.Spec.GraphQLExecutor.Schema, plannerConfig)
	if err != nil {
		log.Errorf("GraphQL execution engine couldn't created: %v", err)
		return
	}

	hooks := &datasource.Hooks{
		PreSendHttpHook:     preSendHttpHook{m},
		PostReceiveHttpHook: postReceiveHttpHook{m},
	}

	httpJSONOptions := gql.DataSourceHttpJsonOptions{
		HttpClient:         m.Spec.GraphQLExecutor.Client,
		WhitelistedSchemes: []string{"tyk"},
		Hooks:              hooks,
	}

	graphQLOptions := gql.DataSourceGraphqlOptions{
		HttpClient:         m.Spec.GraphQLExecutor.Client,
		WhitelistedSchemes: []string{"tyk"},
		Hooks:              hooks,
	}

	errMsgFormat := "%s couldn't be added"

	err = engine.AddHttpJsonDataSourceWithOptions(HTTPJSONDataSource, httpJSONOptions)
	if err != nil {
		m.Logger().WithError(err).Errorf(errMsgFormat, HTTPJSONDataSource)
	}

	err = engine.AddHttpJsonDataSourceWithOptions(TykRESTDataSource, httpJSONOptions)
	if err != nil {
		m.Logger().WithError(err).Errorf(errMsgFormat, HTTPJSONDataSource)
	}

	err = engine.AddGraphqlDataSourceWithOptions(GraphQLDataSource, graphQLOptions)
	if err != nil {
		m.Logger().WithError(err).Errorf(errMsgFormat, GraphQLDataSource)
	}

	err = engine.AddGraphqlDataSourceWithOptions(TykGraphQLDataSource, graphQLOptions)
	if err != nil {
		m.Logger().WithError(err).Errorf(errMsgFormat, GraphQLDataSource)
	}

	err = engine.AddDataSource(SchemaDataSource, datasource.SchemaDataSourcePlannerFactoryFactory{})
	if err != nil {
		m.Logger().WithError(err).Errorf(errMsgFormat, SchemaDataSource)
	}

	m.Spec.GraphQLExecutor.Engine = engine
	m.Spec.GraphQLExecutor.Client = httpJSONOptions.HttpClient
}

func (m *GraphQLMiddleware) initGraphQLEngineV2(logger *abstractlogger.LogrusLogger) {
	configAdapter := adapter.NewGraphQLConfigAdapter(m.Spec.APIDefinition,
		adapter.WithHttpClient(m.Spec.GraphQLExecutor.Client),
		adapter.WithStreamingClient(m.Spec.GraphQLExecutor.StreamingClient),
		adapter.WithSchema(m.Spec.GraphQLExecutor.Schema),
	)

	engineConfig, err := configAdapter.EngineConfigV2()
	if err != nil {
		m.Logger().WithError(err).Error("could not create engine v2 config")
		return
	}
	engineConfig.SetWebsocketBeforeStartHook(m)

	specCtx, cancel := context.WithCancel(context.Background())
	engine, err := gql.NewExecutionEngineV2(specCtx, logger, *engineConfig)
	if err != nil {
		m.Logger().WithError(err).Error("could not create execution engine v2")
		cancel()
		return
	}

	m.Spec.GraphQLExecutor.EngineV2 = engine
	m.Spec.GraphQLExecutor.CancelV2 = cancel
	m.Spec.GraphQLExecutor.HooksV2.BeforeFetchHook = m
	m.Spec.GraphQLExecutor.HooksV2.AfterFetchHook = m

	if m.isSupergraphAPIDefinition() {
		m.loadSupergraphMergedSDLAsSchema()
	}
}

func (m *GraphQLMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	err := m.checkForUnsupportedUsage()
	if err != nil {
		m.Logger().WithError(err).Error("request could not be executed because of unsupported usage")
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if m.Spec.GraphQLExecutor.Schema == nil {
		m.Logger().Error("Schema is not created")
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if websocket.IsWebSocketUpgrade(r) {
		if !m.websocketUpgradeAllowed() {
			return errors.New("websockets are not allowed"), http.StatusUnprocessableEntity
		}

		if !m.websocketUpgradeUsesGraphQLProtocol(r) {
			return errors.New("invalid websocket protocol for upgrading to a graphql websocket connection"), http.StatusBadRequest
		}

		ctxSetGraphQLIsWebSocketUpgrade(r, true)
		return nil, http.StatusSwitchingProtocols
	}

	// With current in memory server approach we need body to be readable again
	// as for proxy only API we are sending it as is
	nopCloseRequestBody(r)

	var gqlRequest gql.Request
	err = gql.UnmarshalRequest(r.Body, &gqlRequest)
	if err != nil {
		m.Logger().Debugf("Error while unmarshalling GraphQL request: '%s'", err)
		return err, http.StatusBadRequest
	}

	defer ctxSetGraphQLRequest(r, &gqlRequest)

	normalizationResult, err := gqlRequest.Normalize(m.Spec.GraphQLExecutor.Schema)
	if err != nil {
		m.Logger().Errorf("Error while normalizing GraphQL request: '%s'", err)
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if normalizationResult.Errors != nil && normalizationResult.Errors.Count() > 0 {
		return m.writeGraphQLError(w, normalizationResult.Errors)
	}

	validationResult, err := gqlRequest.ValidateForSchema(m.Spec.GraphQLExecutor.Schema)
	if err != nil {
		m.Logger().Errorf("Error while validating GraphQL request: '%s'", err)
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if validationResult.Errors != nil && validationResult.Errors.Count() > 0 {
		return m.writeGraphQLError(w, validationResult.Errors)
	}

	return nil, http.StatusOK
}

func (m *GraphQLMiddleware) writeGraphQLError(w http.ResponseWriter, errors gql.Errors) (error, int) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(http.StatusBadRequest)
	_, _ = errors.WriteResponse(w)
	m.Logger().Debugf("Error while validating GraphQL request: '%s'", errors)
	return errCustomBodyResponse, http.StatusBadRequest
}

func (m *GraphQLMiddleware) websocketUpgradeUsesGraphQLProtocol(r *http.Request) bool {
	websocketProtocol := r.Header.Get(header.SecWebSocketProtocol)
	return websocketProtocol == GraphQLWebSocketProtocol
}

func (m *GraphQLMiddleware) checkForUnsupportedUsage() error {
	if m.isGraphQLConfigVersion1() && m.isSupergraphAPIDefinition() {
		return errors.New("supergraph execution mode is not supported for graphql config version 1 - please use version 2")
	}

	return nil
}

func (m *GraphQLMiddleware) isGraphQLConfigVersion1() bool {
	return m.Spec.GraphQL.Version == apidef.GraphQLConfigVersion1 || m.Spec.GraphQL.Version == apidef.GraphQLConfigVersionNone
}

func (m *GraphQLMiddleware) isSupergraphAPIDefinition() bool {
	return m.Spec.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeSupergraph
}

func (m *GraphQLMiddleware) loadSupergraphMergedSDLAsSchema() {
	m.Spec.GraphQL.Schema = m.Spec.GraphQL.Supergraph.MergedSDL
}

// OnBeforeStart - is a graphql.WebsocketBeforeStartHook which allows to perform security checks for all operations over websocket connections
func (m *GraphQLMiddleware) OnBeforeStart(reqCtx context.Context, operation *gql.Request) error {
	if m.Spec.UseKeylessAccess {
		return nil
	}

	v := reqCtx.Value(ctx.SessionData)
	if v == nil {
		m.Logger().Error("failed to get session in OnBeforeStart hook")
		return errors.New("empty session")
	}
	session := v.(*user.SessionState)

	accessDef, _, err := GetAccessDefinitionByAPIIDOrSession(session, m.Spec)
	if err != nil {
		m.Logger().Errorf("failed to get access definition in OnBeforeStart hook: '%s'", err)
		return err
	}

	complexityCheck := &GraphqlComplexityChecker{logger: m.Logger()}
	depthResult := complexityCheck.DepthLimitExceeded(operation, accessDef, m.Spec.GraphQLExecutor.Schema)
	switch depthResult {
	case ComplexityFailReasonInternalError:
		return ProxyingRequestFailedErr
	case ComplexityFailReasonDepthLimitExceeded:
		return GraphQLDepthLimitExceededErr
	}

	granularAccessCheck := &GraphqlGranularAccessChecker{}
	result := granularAccessCheck.CheckGraphqlRequestFieldAllowance(operation, accessDef, m.Spec.GraphQLExecutor.Schema)
	switch result.failReason {
	case GranularAccessFailReasonInternalError:
		m.Logger().Errorf(RestrictedFieldValidationFailedLogMsg, result.internalErr)
		return ProxyingRequestFailedErr
	case GranularAccessFailReasonValidationError:
		m.Logger().Debugf(RestrictedFieldValidationFailedLogMsg, result.validationResult.Errors)
		return result.validationResult.Errors
	}

	return nil
}

func (m *GraphQLMiddleware) OnBeforeFetch(ctx resolve.HookContext, input []byte) {
	m.BaseMiddleware.Logger().
		WithFields(
			logrus.Fields{
				"path": ctx.CurrentPath,
			},
		).Debugf("%s (beforeFetchHook): %s", ctx.CurrentPath, string(input))
}

func (m *GraphQLMiddleware) OnData(ctx resolve.HookContext, output []byte, singleFlight bool) {
	m.BaseMiddleware.Logger().
		WithFields(
			logrus.Fields{
				"path":          ctx.CurrentPath,
				"single_flight": singleFlight,
			},
		).Debugf("%s (afterFetchHook.OnData): %s", ctx.CurrentPath, string(output))
}

func (m *GraphQLMiddleware) OnError(ctx resolve.HookContext, output []byte, singleFlight bool) {
	m.BaseMiddleware.Logger().
		WithFields(
			logrus.Fields{
				"path":          ctx.CurrentPath,
				"single_flight": singleFlight,
			},
		).Debugf("%s (afterFetchHook.OnError): %s", ctx.CurrentPath, string(output))
}

func (m *GraphQLMiddleware) websocketUpgradeAllowed() bool {
	if !m.Gw.GetConfig().HttpServerOptions.EnableWebSockets {
		return false
	}

	if m.Spec.GraphQL.Version == apidef.GraphQLConfigVersion1 || m.Spec.GraphQL.Version == apidef.GraphQLConfigVersionNone {
		return false
	}

	return true
}

func needsGraphQLExecutionEngine(apiSpec *APISpec) bool {
	switch apiSpec.GraphQL.ExecutionMode {
	case apidef.GraphQLExecutionModeExecutionEngine,
		apidef.GraphQLExecutionModeSupergraph:
		return true
	case apidef.GraphQLExecutionModeSubgraph:
		return true
	case apidef.GraphQLExecutionModeProxyOnly:
		if apiSpec.GraphQL.Version == apidef.GraphQLConfigVersion2 {
			return true
		}
	}
	return false
}

func isGraphQLProxyOnly(apiSpec *APISpec) bool {
	return apiSpec.GraphQL.Enabled &&
		(apiSpec.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeProxyOnly || apiSpec.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeSubgraph)
}

func absLoggerLevel(level logrus.Level) abstractlogger.Level {
	switch level {
	case logrus.ErrorLevel:
		return abstractlogger.ErrorLevel
	case logrus.WarnLevel:
		return abstractlogger.WarnLevel
	case logrus.DebugLevel:
		return abstractlogger.DebugLevel
	}
	return abstractlogger.InfoLevel
}

type preSendHttpHook struct {
	m *GraphQLMiddleware
}

func (p preSendHttpHook) Execute(ctx datasource.HookContext, req *http.Request) {
	p.m.BaseMiddleware.Logger().
		WithFields(
			logrus.Fields{
				"typename":     ctx.TypeName,
				"fieldname":    ctx.FieldName,
				"upstream_url": req.URL.String(),
			},
		).Debugf("%s.%s: preSendHttpHook executed", ctx.TypeName, ctx.FieldName)
}

type postReceiveHttpHook struct {
	m *GraphQLMiddleware
}

func (p postReceiveHttpHook) Execute(ctx datasource.HookContext, resp *http.Response, body []byte) {
	p.m.BaseMiddleware.Logger().
		WithFields(
			logrus.Fields{
				"typename":      ctx.TypeName,
				"fieldname":     ctx.FieldName,
				"response_body": string(body),
				"status_code":   resp.StatusCode,
			},
		).Debugf("%s.%s: postReceiveHttpHook executed", ctx.TypeName, ctx.FieldName)
}
