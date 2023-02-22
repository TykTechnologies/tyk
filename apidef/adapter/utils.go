package adapter

import (
	"net/http"
)

func convertApiDefinitionHeadersToHttpHeaders(apiDefHeaders map[string]string) http.Header {
	if len(apiDefHeaders) == 0 {
		return nil
	}

	engineV2Headers := make(http.Header)
	for apiDefHeaderKey, apiDefHeaderValue := range apiDefHeaders {
		engineV2Headers.Add(apiDefHeaderKey, apiDefHeaderValue)
	}

	return engineV2Headers
}
