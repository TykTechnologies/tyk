package graphengine

import (
	"net/http"

	gql "github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/header"
)

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

func writeGraphQLError(logger abstractlogger.Logger, w http.ResponseWriter, errors gql.Errors) (error, int) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(http.StatusBadRequest)
	_, _ = errors.WriteResponse(w)
	//m.Logger().Debugf("Error while validating GraphQL request: '%s'", errors)
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
		//m.Logger().Errorf(RestrictedFieldValidationFailedLogMsg, result.internalErr)
		logger.Error(restrictedFieldValidationFailedLogMsg, abstractlogger.Error(result.InternalErr))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	case GranularAccessFailReasonValidationError:
		w.Header().Set(header.ContentType, header.ApplicationJSON)
		w.WriteHeader(http.StatusBadRequest)
		//_, _ = result.validationResult.Errors.WriteResponse(w)
		if result.writeErrorResponse != nil {
			_, _ = result.writeErrorResponse(w, result.ValidationError)
		}

		//m.Logger().Debugf(RestrictedFieldValidationFailedLogMsg, result.validationResult.Errors)
		logger.Debug(restrictedFieldValidationFailedLogMsg, abstractlogger.Error(result.ValidationError))
		return errCustomBodyResponse, http.StatusBadRequest
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
