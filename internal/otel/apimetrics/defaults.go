package apimetrics

// DefaultAPIMetrics returns the built-in RED instrument definitions used when
// the api_metrics config field is nil (omitted). These provide lean RED metrics
// out of the box with low-cardinality dimensions.
func DefaultAPIMetrics() []APIMetricDefinition {
	return []APIMetricDefinition{
		{
			Name:            "http.server.request.duration",
			Type:            "histogram",
			Description:     "End-to-end request latency",
			HistogramSource: "total",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "method", Label: "http.request.method"},
				{Source: "metadata", Key: "response_code", Label: "http.response.status_code"},
				{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
				{Source: "metadata", Key: "response_flag", Label: "tyk.response_flag"},
			},
		},
		{
			Name:            "tyk.gateway.request.duration",
			Type:            "histogram",
			Description:     "Gateway processing time",
			HistogramSource: "gateway",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "method", Label: "http.request.method"},
				{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
				{Source: "metadata", Key: "response_flag", Label: "tyk.response_flag"},
			},
		},
		{
			Name:            "tyk.upstream.request.duration",
			Type:            "histogram",
			Description:     "Upstream response time",
			HistogramSource: "upstream",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "method", Label: "http.request.method"},
				{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
				{Source: "metadata", Key: "response_flag", Label: "tyk.response_flag"},
			},
		},
		{
			Name:        "tyk.api.requests.total",
			Type:        "counter",
			Description: "Request count with identity dimensions",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "method", Label: "http.request.method"},
				{Source: "metadata", Key: "response_code", Label: "http.response.status_code"},
				{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
				{Source: "session", Key: "api_key", Label: "tyk.api.key"},
				{Source: "session", Key: "oauth_id", Label: "tyk.api.oauth_id"},
			},
		},
	}
}
