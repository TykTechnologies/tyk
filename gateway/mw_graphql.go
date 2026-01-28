package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/pkg/execution/datasource"
	gqlwebsocket "github.com/TykTechnologies/graphql-go-tools/pkg/subscription/websocket"

	"github.com/TykTechnologies/tyk/internal/graphengine"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/user"

	gql "github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	gqlv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
)

var (
	ProxyingRequestFailedErr     = errors.New("there was a problem proxying the request")
	GraphQLDepthLimitExceededErr = errors.New("depth limit exceeded")
)

type GraphQLMiddleware struct {
	*BaseMiddleware
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

	reusableBodyReadCloser := func(buf io.ReadCloser) (io.ReadCloser, error) {
		return newNopCloserBuffer(buf)
	}

	if m.Spec.GraphQL.Version == apidef.GraphQLConfigVersionNone || m.Spec.GraphQL.Version == apidef.GraphQLConfigVersion1 {
		if m.Spec.GraphQL.Version == apidef.GraphQLConfigVersionNone {
			log.Warn("GraphQL config version is not set, defaulting to version 1")
		}

		log.Info("GraphQL Config Version 1 is deprecated - Please consider migrating to version 2 or higher")
		m.Spec.GraphEngine, err = graphengine.NewEngineV1(graphengine.EngineV1Options{
			Logger:        log,
			ApiDefinition: m.Spec.APIDefinition,
			Schema:        schema,
			HttpClient: &http.Client{
				Transport: &http.Transport{TLSClientConfig: tlsClientConfig(m.Spec, nil)},
			},
			Injections: graphengine.EngineV1Injections{
				PreSendHttpHook:           preSendHttpHook{m},
				PostReceiveHttpHook:       postReceiveHttpHook{m},
				ContextStoreRequest:       ctxSetGraphQLRequest,
				ContextRetrieveRequest:    ctxGetGraphQLRequest,
				NewReusableBodyReadCloser: reusableBodyReadCloser,
			},
		})
	} else if m.Spec.GraphQL.Version == apidef.GraphQLConfigVersion2 {
		httpClient := &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsClientConfig(m.Spec, nil)},
		}
		m.Spec.GraphEngine, err = graphengine.NewEngineV2(graphengine.EngineV2Options{
			Logger:          log,
			Schema:          schema,
			ApiDefinition:   m.Spec.APIDefinition,
			HttpClient:      httpClient,
			StreamingClient: httpClient,
			OpenTelemetry: graphengine.EngineV2OTelConfig{
				Enabled:        m.Gw.GetConfig().OpenTelemetry.Enabled,
				TracerProvider: m.Gw.TracerProvider,
			},
			Injections: graphengine.EngineV2Injections{
				BeforeFetchHook:           m,
				AfterFetchHook:            m,
				WebsocketOnBeforeStart:    m,
				ContextStoreRequest:       ctxSetGraphQLRequest,
				ContextRetrieveRequest:    ctxGetGraphQLRequest,
				NewReusableBodyReadCloser: reusableBodyReadCloser,
				SeekReadCloser: func(readCloser io.ReadCloser) (io.ReadCloser, error) {
					body, ok := readCloser.(*nopCloserBuffer)
					if !ok {
						return nil, nil
					}
					_, err := body.Seek(0, io.SeekStart)
					if err != nil {
						return nil, err
					}
					return body, nil
				},
				TykVariableReplacer: m.Gw.ReplaceTykVariables,
			},
		})
	} else if m.Spec.GraphQL.Version == apidef.GraphQLConfigVersion3Preview {
		v2Schema, err := gqlv2.NewSchemaFromString(m.Spec.GraphQL.Schema)
		if err != nil {
			log.Errorf("Error while creating schema from API definition: %v", err)
			return
		}
		engine, err := graphengine.NewEngineV3(graphengine.EngineV3Options{
			Logger:        log,
			Schema:        v2Schema,
			ApiDefinition: m.Spec.APIDefinition,
			OpenTelemetry: graphengine.EngineV2OTelConfig{
				Enabled:        m.Gw.GetConfig().OpenTelemetry.Enabled,
				TracerProvider: m.Gw.TracerProvider,
			},
			HttpClient: &http.Client{
				Transport: &http.Transport{TLSClientConfig: tlsClientConfig(m.Spec, nil)},
			},
			Injections: graphengine.EngineV3Injections{
				ContextRetrieveRequest: ctxGetGraphQLRequestV2,
				ContextStoreRequest:    ctxSetGraphQLRequestV2,
				// TODO use proper version or request for this
				//WebsocketOnBeforeStart:    m,
				NewReusableBodyReadCloser: reusableBodyReadCloser,
				SeekReadCloser: func(readCloser io.ReadCloser) (io.ReadCloser, error) {
					body, ok := readCloser.(*nopCloserBuffer)
					if !ok {
						return nil, nil
					}
					_, err := body.Seek(0, io.SeekStart)
					if err != nil {
						return nil, err
					}
					return body, nil
				},
				TykVariableReplacer: m.Gw.ReplaceTykVariables,
			},
		})
		if err != nil {
			log.Errorf("Error creating enginev3: %v", err)
			return
		}
		m.Spec.GraphEngine = engine
	} else {
		log.Errorf("Could not init GraphQL middleware: invalid config version provided: %s", m.Spec.GraphQL.Version)
	}
}

func (m *GraphQLMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	err := m.checkForUnsupportedUsage()
	if err != nil {
		m.Logger().WithError(err).Error("request could not be executed because of unsupported usage")
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if m.Spec.GraphEngine == nil {
		m.Logger().Error("GraphEngine is not initialized")
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if !m.Spec.GraphEngine.HasSchema() {
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

	return m.Spec.GraphEngine.ProcessAndStoreGraphQLRequest(w, r)
}

func (m *GraphQLMiddleware) websocketUpgradeUsesGraphQLProtocol(r *http.Request) bool {
	websocketProtocol := r.Header.Get(header.SecWebSocketProtocol)
	return websocketProtocol == string(gqlwebsocket.ProtocolGraphQLWS) ||
		websocketProtocol == string(gqlwebsocket.ProtocolGraphQLTransportWS)
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

// OnBeforeStart - is a graphql.WebsocketBeforeStartHook which allows to perform security checks for all operations over websocket connections
func (m *GraphQLMiddleware) OnBeforeStart(reqCtx context.Context, operation *gql.Request) error {
	if m.Spec.UseKeylessAccess {
		return nil
	}

	schema, err := graphengine.GetSchemaV1(m.Spec.GraphEngine)
	if err != nil {
		return err
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
	depthResult := complexityCheck.DepthLimitExceeded(operation, accessDef, schema)
	switch depthResult {
	case ComplexityFailReasonInternalError:
		return ProxyingRequestFailedErr
	case ComplexityFailReasonDepthLimitExceeded:
		return GraphQLDepthLimitExceededErr
	}

	granularAccessCheck := &GraphqlGranularAccessChecker{}
	result := granularAccessCheck.CheckGraphqlRequestFieldAllowance(operation, accessDef, schema)
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
		if apiSpec.GraphQL.Version == apidef.GraphQLConfigVersion2 || apiSpec.GraphQL.Version == apidef.GraphQLConfigVersion3Preview {
			return true
		}
	}
	return false
}

func isGraphQLProxyOnly(apiSpec *APISpec) bool {
	return apiSpec.GraphQL.Enabled &&
		(apiSpec.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeProxyOnly || apiSpec.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeSubgraph)
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
