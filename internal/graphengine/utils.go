package graphengine

import (
	"errors"
	"net"
	"net/http"

	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	graphqlv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/header"
)

type TykVariableReplacer func(r *http.Request, in string, escape bool) string

func GetSchemaV1(engine Engine) (*graphql.Schema, error) {
	switch engine.Version() {
	case EngineVersionV1:
		return engine.(*EngineV1).Schema, nil
	case EngineVersionV2:
		return engine.(*EngineV2).Schema, nil
	}
	return nil, errors.New("schema not supported for engine type")
}

func GetSchemaV2(engine Engine) (*graphqlv2.Schema, error) {
	switch engine.Version() {
	case EngineVersionV3:
		// Handle for tyk graph engine v3
	}
	return nil, errors.New("schema not supported for engine type")
}

func createAbstractLogrusLogger(logger *logrus.Logger) *abstractlogger.LogrusLogger {
	return abstractlogger.NewLogrusLogger(logger, absLoggerLevel(logger.Level))
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

func writeGraphQLError(logger abstractlogger.Logger, w http.ResponseWriter, errors graphql.Errors) (error, int) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(http.StatusBadRequest)
	_, _ = errors.WriteResponse(w)
	logger.Error("error while validating GraphQL request", abstractlogger.Error(errors))
	return errCustomBodyResponse, http.StatusBadRequest
}

func complexityFailReasonAsHttpStatusCode(failReason ComplexityFailReason) (error, int) {
	switch failReason {
	case ComplexityFailReasonInternalError:
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	case ComplexityFailReasonDepthLimitExceeded:
		return GraphQLDepthLimitExceededErr, http.StatusForbidden
	}

	return nil, http.StatusOK
}

func granularAccessFailReasonAsHttpStatusCode(logger abstractlogger.Logger, result *GraphQLGranularAccessResult, w http.ResponseWriter) (error, int) {
	const restrictedFieldValidationFailedLogMsg = "error during GraphQL request restricted fields validation"

	switch result.FailReason {
	case GranularAccessFailReasonNone:
		return nil, http.StatusOK
	case GranularAccessFailReasonInternalError:
		logger.Error(restrictedFieldValidationFailedLogMsg, abstractlogger.Error(result.InternalErr))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	case GranularAccessFailReasonValidationError:
		w.Header().Set(header.ContentType, header.ApplicationJSON)
		w.WriteHeader(http.StatusBadRequest)
		if result.writeErrorResponse != nil {
			_, _ = result.writeErrorResponse(w, result.ValidationError)
		}

		logger.Debug(restrictedFieldValidationFailedLogMsg, abstractlogger.Error(result.ValidationError))
		return errCustomBodyResponse, http.StatusBadRequest
	case GranularAccessFailReasonIntrospectionDisabled:
		w.WriteHeader(http.StatusForbidden)
		logger.Debug("introspection disabled")
		return ErrIntrospectionDisabled, http.StatusForbidden
	}

	return nil, http.StatusOK
}

func greaterThanIntConsideringUnlimited(first, second int) bool {
	if first == -1 {
		return true
	}

	if second == -1 {
		return false
	}

	return first > second
}

func isSupergraph(apiDefinition *apidef.APIDefinition) bool {
	return apiDefinition.GraphQL.Enabled && apiDefinition.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeSupergraph
}

func isProxyOnly(apiDefinition *apidef.APIDefinition) bool {
	return apiDefinition.GraphQL.Enabled &&
		(apiDefinition.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeProxyOnly || apiDefinition.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeSubgraph)
}

func additionalUpstreamHeaders(logger abstractlogger.Logger, outreq *http.Request, apiDefinition *apidef.APIDefinition) http.Header {
	upstreamHeaders := http.Header{}
	switch apiDefinition.GraphQL.ExecutionMode {
	case apidef.GraphQLExecutionModeSupergraph:
		// if this context vars are enabled and this is a supergraph, inject the sub request id header
		if !apiDefinition.EnableContextVars {
			break
		}
		ctxData := ctxGetData(outreq)
		if reqID, exists := ctxData["request_id"]; !exists {
			logger.Warn("context variables enabled but request_id missing")
		} else if requestID, ok := reqID.(string); ok {
			upstreamHeaders.Set("X-Tyk-Parent-Request-Id", requestID)
		}
	case apidef.GraphQLExecutionModeExecutionEngine:
		globalHeaders := headerStructToHeaderMap(apiDefinition.GraphQL.Engine.GlobalHeaders)
		for key, value := range globalHeaders {
			upstreamHeaders.Set(key, value)
		}
	}

	return upstreamHeaders
}

func headerStructToHeaderMap(headers []apidef.UDGGlobalHeader) map[string]string {
	headerMap := make(map[string]string)
	for _, header := range headers {
		headerMap[header.Key] = header.Value
	}
	return headerMap
}

func ctxGetData(r *http.Request) map[string]interface{} {
	if v := r.Context().Value(ctx.ContextData); v != nil {
		return v.(map[string]interface{})
	}
	return nil
}

func websocketConnWithUpgradeHeader(logger abstractlogger.Logger, params *ReverseProxyParams) (underlyingConn net.Conn, err error) {
	conn, err := params.WebSocketUpgrader.Upgrade(params.ResponseWriter, params.OutRequest, http.Header{
		header.SecWebSocketProtocol: {params.OutRequest.Header.Get(header.SecWebSocketProtocol)},
	})
	if err != nil {
		logger.Error("websocket upgrade for GraphQL engine failed", abstractlogger.Error(err))
		return nil, err
	}

	return conn.NetConn(), nil
}
