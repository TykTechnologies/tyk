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
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/astparser"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/federation"

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
		// Apollo Federation features (`_entities`, `_service`, schema augmentation)
		// only run under GraphQL config version 3. A schema with `@key` directives
		// under version 2 silently behaves as a plain GraphQL API — federation
		// queries fail with "field not defined" and there's no signal to the
		// operator that they're on the wrong version. Surface a warning so
		// customers can discover the migration path. We don't block API loading:
		// `@key` may legitimately appear for non-federation reasons.
		if schemaHasKeyDirective(m.Spec.GraphQL.Schema) {
			log.Warnf("API %s declares `@key` directives but uses GraphQL version 2; federation features are only available under version 3 (Preview). Set graphql.version to \"3\" to enable Apollo Federation v2 support.", m.Spec.APIID)
		}
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
				Enabled:        m.Gw.GetConfig().OpenTelemetry.TracesEnabled(),
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
		schemaStr := m.Spec.GraphQL.Schema
		// Apollo Federation v2 schemas need the federation extensions
		// (`_Entity` union, `_entities`, `_service`) injected before the schema
		// is parsed so validation accepts incoming federation queries. UDG
		// composes upstreams locally; proxy-only forwards `_entities` queries
		// to an upstream subgraph or router, but Tyk still validates the
		// operation against its known schema first. In both cases, augment
		// the schema. For proxy-only we auto-detect federation by scanning
		// for `@key` directives — no config flag.
		if m.Spec.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeExecutionEngine {
			var err error
			schemaStr, err = federation.BuildFederationSchema(schemaStr, schemaStr)
			if err != nil {
				log.Errorf("Error while injecting federation schema: %v", err)
				return
			}
		} else if m.Spec.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeProxyOnly && schemaHasKeyDirective(schemaStr) {
			// Apollo Federation v2 proxy-mode passthrough: when the customer's
			// SDL declares `@key` types, Tyk forwards `_entities` queries to the
			// upstream subgraph or router. Tyk still validates the operation
			// against its known schema first, so we must inject the federation
			// extensions (`_Entity` union, `_entities`, `_service`) here.
			// Auto-detect from `@key` — no config flag.
			augmented, err := federation.BuildFederationSchema(schemaStr, schemaStr)
			if err != nil {
				log.Errorf("Error while injecting federation schema: %v", err)
				return
			}
			schemaStr = augmented
		}

		v2Schema, err := gqlv2.NewSchemaFromString(schemaStr)
		if err != nil {
			log.Errorf("Error while creating schema from API definition: %v", err)
			return
		}
		v3HttpClient := &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsClientConfig(m.Spec, nil)},
		}
		// Use a SEPARATE *http.Client instance for streaming. The HttpClient
		// passed via EngineV3Options is captured by reverseProxyPreHandlerV2,
		// which mutates `httpClient.Transport` on every reverse-proxy
		// PreHandle to wrap it in GraphQLEngineTransport. That wrapped
		// transport assumes a Tyk-gateway request context (proxy-only / UDG
		// values) and panics under the bare WebSocket dial path used by the
		// upstream graphql_datasource subscription client. By giving the
		// streaming client its own transport we keep the SSE / WS upstream
		// dial untouched. V2 has the same shape but never gets exercised by
		// tests because V2's existing subscription tests never reach the
		// upstream-dial path.
		v3StreamingClient := &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsClientConfig(m.Spec, nil)},
			Timeout:   0,
		}
		engine, err := graphengine.NewEngineV3(graphengine.EngineV3Options{
			Logger:        log,
			Schema:        v2Schema,
			ApiDefinition: m.Spec.APIDefinition,
			OpenTelemetry: graphengine.EngineV2OTelConfig{
				Enabled:        m.Gw.GetConfig().OpenTelemetry.TracesEnabled(),
				TracerProvider: m.Gw.TracerProvider,
			},
			HttpClient: v3HttpClient,
			// V2 sets StreamingClient on its options so the graphql-go-tools
			// subscription client picks up our TLS config and any future
			// timeout/transport tuning. V3 inherits the same expectation: SSE
			// upstreams and graphql_datasource subscription clients must use
			// the configured client, not the library default.
			StreamingClient: v3StreamingClient,
			Injections: graphengine.EngineV3Injections{
				ContextRetrieveRequest: ctxGetGraphQLRequestV2,
				ContextStoreRequest:    ctxSetGraphQLRequestV2,
				// V3 subscriptions go through the same depth-limit and
				// granular-access policy gates as V2. The hook receives a v2
				// Request; OnBeforeStartV2 mirrors OnBeforeStart but operates
				// on the v2 schema/Request types.
				WebsocketOnBeforeStart:    onBeforeStartV2HookFor(m),
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

// resolveWebsocketAccessDefinition is the lowest-common-denominator policy
// pre-check shared between V1's `gql.Request` hook and V3's `graphqlv2.Request`
// hook. It resolves the session's AccessDefinition for the current API and
// reports whether websocket-policy checks should run at all.
//
// Returns:
//   - (nil, false, nil) when the API is keyless — checks are bypassed.
//   - (nil, false, err) when the session is missing or the access definition
//     cannot be resolved.
//   - (accessDef, true, nil) when the caller should proceed with depth-limit
//     and granular-access validation against its version's typed Request.
//
// The actual depth-limit and granular-access checks are version-specific —
// the v1 and v2 graphql Request types share method names but are distinct Go
// types — so each adapter calls into its own `GraphqlComplexityChecker` /
// `GraphqlGranularAccessChecker` (v1) or the v2-typed equivalents using the
// same AccessDefinition returned here.
func (m *GraphQLMiddleware) resolveWebsocketAccessDefinition(reqCtx context.Context) (accessDef *user.AccessDefinition, shouldCheck bool, err error) {
	if m.Spec.UseKeylessAccess {
		return nil, false, nil
	}

	v := reqCtx.Value(ctx.SessionData)
	if v == nil {
		m.Logger().Error("failed to get session in OnBeforeStart hook")
		return nil, false, errors.New("empty session")
	}
	session := v.(*user.SessionState)

	accessDef, _, err = GetAccessDefinitionByAPIIDOrSession(session, m.Spec)
	if err != nil {
		m.Logger().Errorf("failed to get access definition in OnBeforeStart hook: '%s'", err)
		return nil, false, err
	}
	return accessDef, true, nil
}

// OnBeforeStart - is a graphql.WebsocketBeforeStartHook which allows to perform security checks for all operations over websocket connections
func (m *GraphQLMiddleware) OnBeforeStart(reqCtx context.Context, operation *gql.Request) error {
	accessDef, shouldCheck, err := m.resolveWebsocketAccessDefinition(reqCtx)
	if err != nil {
		return err
	}
	if !shouldCheck {
		return nil
	}

	schema, err := graphengine.GetSchemaV1(m.Spec.GraphEngine)
	if err != nil {
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

// graphqlV2WebsocketBeforeStart adapts GraphQLMiddleware to the v2
// WebsocketBeforeStartHook interface. We can't make GraphQLMiddleware itself
// satisfy both v1 and v2 interfaces because both declare an `OnBeforeStart`
// method on the same receiver but with different `*Request` types — Go would
// reject the duplicate method. Wrapping in a thin adapter keeps the v1 hook
// signature (still used by EngineV1) untouched while letting V3 receive a v2
// Request.
type graphqlV2WebsocketBeforeStart struct {
	m *GraphQLMiddleware
}

// OnBeforeStart applies the same depth-limit + granular-access policy as
// (*GraphQLMiddleware).OnBeforeStart but against the v2 `*graphqlv2.Request`
// and v2 schema. The shared `resolveWebsocketAccessDefinition` handles the
// keyless bypass, session lookup, and access-def resolution. The typed checks
// below mirror the v1 hook line-for-line, just on v2 types.
func (h graphqlV2WebsocketBeforeStart) OnBeforeStart(reqCtx context.Context, operation *gqlv2.Request) error {
	accessDef, shouldCheck, err := h.m.resolveWebsocketAccessDefinition(reqCtx)
	if err != nil {
		return err
	}
	if !shouldCheck {
		return nil
	}

	schema, err := graphengine.GetSchemaV2(h.m.Spec.GraphEngine)
	if err != nil {
		return err
	}

	if depthErr := websocketCheckDepthLimitV2(h.m.Logger(), operation, accessDef, schema); depthErr != nil {
		return depthErr
	}

	if accessErr := websocketCheckGranularAccessV2(h.m.Logger(), operation, accessDef, schema); accessErr != nil {
		return accessErr
	}

	return nil
}

// websocketCheckDepthLimitV2 mirrors GraphqlComplexityChecker.DepthLimitExceeded
// but operates on a v2 Request and v2 Schema. Returns nil if the request is
// within the configured depth limits (or if depth limiting is disabled), or
// an error suitable for propagating out of the websocket OnBeforeStart hook.
func websocketCheckDepthLimitV2(logger *logrus.Entry, operation *gqlv2.Request, accessDef *user.AccessDefinition, schema *gqlv2.Schema) error {
	complexityCheck := &GraphqlComplexityChecker{logger: logger}
	if !complexityCheck.DepthLimitEnabled(accessDef) {
		return nil
	}

	isIntrospectionQuery, err := operation.IsIntrospectionQuery()
	if err != nil {
		logger.Debugf("error while checking for introspection query: %s", err.Error())
		return ProxyingRequestFailedErr
	}
	if isIntrospectionQuery {
		return nil
	}

	complexityRes, err := operation.CalculateComplexity(gqlv2.DefaultComplexityCalculator, schema)
	if err != nil {
		logger.Errorf("error while calculating complexity of GraphQL request: %s", err)
		return ProxyingRequestFailedErr
	}
	if complexityRes.Errors != nil && complexityRes.Errors.Count() > 0 {
		logger.Errorf("error while calculating complexity of GraphQL request: %s", complexityRes.Errors.ErrorByIndex(0))
		return ProxyingRequestFailedErr
	}

	if len(accessDef.FieldAccessRights) == 0 {
		if complexityRes.Depth > accessDef.Limit.MaxQueryDepth {
			logger.Debugf("complexity of the request is higher than the allowed limit '%d'", accessDef.Limit.MaxQueryDepth)
			return GraphQLDepthLimitExceededErr
		}
		return nil
	}

	for _, fieldComplexityRes := range complexityRes.PerRootField {
		var (
			fieldAccessDefinition user.FieldAccessDefinition
			hasPerFieldLimits     bool
		)

		for _, fieldAccessRight := range accessDef.FieldAccessRights {
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
			if greaterThanInt(fieldComplexityRes.Depth, fieldAccessDefinition.Limits.MaxQueryDepth) {
				logger.Debugf("Depth '%d' of the root field: %s.%s is higher than the allowed field limit '%d'",
					fieldComplexityRes.Depth, fieldAccessDefinition.TypeName, fieldAccessDefinition.FieldName, fieldAccessDefinition.Limits.MaxQueryDepth)
				return GraphQLDepthLimitExceededErr
			}
			continue
		}

		queryDepth := fieldComplexityRes.Depth + 1
		if greaterThanInt(queryDepth, accessDef.Limit.MaxQueryDepth) {
			logger.Debugf("Depth '%d' of the root field: %s.%s is higher than the allowed global limit '%d'",
				queryDepth, fieldComplexityRes.TypeName, fieldComplexityRes.FieldName, accessDef.Limit.MaxQueryDepth)
			return GraphQLDepthLimitExceededErr
		}
	}
	return nil
}

// websocketCheckGranularAccessV2 mirrors
// GraphqlGranularAccessChecker.CheckGraphqlRequestFieldAllowance for v2
// Request/Schema. Returns nil if the request is allowed, or the validation
// errors otherwise (which the websocket framing layer relays back to the
// client as a `{"type":"error", ...}` frame).
func websocketCheckGranularAccessV2(logger *logrus.Entry, operation *gqlv2.Request, accessDef *user.AccessDefinition, schema *gqlv2.Schema) error {
	if len(accessDef.AllowedTypes) == 0 && len(accessDef.RestrictedTypes) == 0 {
		return nil
	}

	var fieldRestrictionList gqlv2.FieldRestrictionList
	if len(accessDef.AllowedTypes) != 0 {
		types := make([]gqlv2.Type, 0, len(accessDef.AllowedTypes))
		for _, t := range accessDef.AllowedTypes {
			types = append(types, gqlv2.Type{Name: t.Name, Fields: t.Fields})
		}
		fieldRestrictionList = gqlv2.FieldRestrictionList{Kind: gqlv2.AllowList, Types: types}
	} else {
		types := make([]gqlv2.Type, 0, len(accessDef.RestrictedTypes))
		for _, t := range accessDef.RestrictedTypes {
			types = append(types, gqlv2.Type{Name: t.Name, Fields: t.Fields})
		}
		fieldRestrictionList = gqlv2.FieldRestrictionList{Kind: gqlv2.BlockList, Types: types}
	}

	result, err := operation.ValidateFieldRestrictions(schema, fieldRestrictionList, gqlv2.DefaultFieldsValidator{})
	if err != nil {
		logger.Errorf(RestrictedFieldValidationFailedLogMsg, err)
		return ProxyingRequestFailedErr
	}
	if !result.Valid || (result.Errors != nil && result.Errors.Count() > 0) {
		logger.Debugf(RestrictedFieldValidationFailedLogMsg, result.Errors)
		return result.Errors
	}
	return nil
}

// onBeforeStartV2HookFor returns the v2 WebsocketBeforeStartHook used by V3.
// Defined as a constructor (rather than embedding the adapter directly in
// EngineV3Injections) so the call site reads as `WebsocketOnBeforeStart:
// onBeforeStartV2HookFor(m)` matching the V2 wiring `WebsocketOnBeforeStart: m`.
func onBeforeStartV2HookFor(m *GraphQLMiddleware) gqlv2.WebsocketBeforeStartHook {
	return graphqlV2WebsocketBeforeStart{m: m}
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

// schemaHasKeyDirective parses the given SDL and reports whether any object
// type definition or extension carries the `@key` directive. This is the
// auto-detection signal for Apollo Federation v2 in proxy mode — no config
// flag is required. Mirrors `keyedEntityTypes` in the enginev3 package; we
// duplicate the small parser here to avoid pulling the gateway into the
// enginev3 dependency graph for a 20-line helper.
func schemaHasKeyDirective(sdl string) bool {
	doc, report := astparser.ParseGraphqlDocumentString(sdl)
	if report.HasErrors() {
		return false
	}
	for i := range doc.ObjectTypeDefinitions {
		def := doc.ObjectTypeDefinitions[i]
		if !def.HasDirectives {
			continue
		}
		for _, dRef := range def.Directives.Refs {
			if doc.DirectiveNameString(dRef) == "key" {
				return true
			}
		}
	}
	for i := range doc.ObjectTypeExtensions {
		ext := doc.ObjectTypeExtensions[i]
		if !ext.HasDirectives {
			continue
		}
		for _, dRef := range ext.Directives.Refs {
			if doc.DirectiveNameString(dRef) == "key" {
				return true
			}
		}
	}
	return false
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
