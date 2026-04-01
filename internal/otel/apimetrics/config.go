package apimetrics

import "encoding/json"

// APIMetricDefinitions is a named slice type that implements envconfig.Decoder,
// allowing api_metrics to be set via environment variables as a JSON string.
type APIMetricDefinitions []APIMetricDefinition

// Decode implements the envconfig.Decoder interface so that envconfig can parse
// a JSON-encoded string into the slice. This enables setting api_metrics via:
//
//	TYK_GW_OPENTELEMETRY_METRICS_APIMETRICS=[{"name":"my.counter","type":"counter",...}]
func (d *APIMetricDefinitions) Decode(value string) error {
	return json.Unmarshal([]byte(value), d)
}

// APIMetricDefinition describes a single metric instrument created at startup.
type APIMetricDefinition struct {
	// Name is the OTel instrument name (e.g. "http.server.request.duration").
	Name string `json:"name"`
	// Type is the instrument type: "counter" or "histogram".
	Type string `json:"type"`
	// Description is the human-readable instrument description.
	Description string `json:"description"`
	// HistogramSource tells the recording path which value to record for histograms.
	// Valid values: "total", "gateway", "upstream".
	// Required for histogram type, ignored for counters.
	HistogramSource string `json:"histogram_source,omitempty"`
	// Dimensions lists the dimensions this instrument records.
	// Each dimension specifies a source, extraction key, OTel label, and optional default.
	Dimensions []DimensionDefinition `json:"dimensions"`
	// HistogramBuckets overrides default bucket boundaries for histograms.
	// Ignored for counters. If empty, uses DefaultLatencyBucketsSeconds.
	HistogramBuckets []float64 `json:"histogram_buckets,omitempty"`
	// Filters restrict which requests are recorded by this instrument.
	// If omitted, all requests are recorded.
	Filters *MetricFilters `json:"filters,omitempty"`
}

// DimensionDefinition describes a single dimension (OTel attribute) for an instrument.
type DimensionDefinition struct {
	// Source is where to extract the value from.
	// Valid values: "metadata", "session", "header", "context", "response_header".
	Source string `json:"source"`
	// Key is the field name within the source (e.g. "method", "X-Customer-ID", "tier").
	Key string `json:"key"`
	// Label is the OTel attribute name in exported data.
	// If omitted, defaults to Key.
	Label string `json:"label,omitempty"`
	// Default is the fallback value when the source is empty or unavailable.
	// If omitted, empty string is used.
	Default string `json:"default,omitempty"`
}

// MetricFilters restrict which requests are recorded by an instrument.
type MetricFilters struct {
	// APIIDs restricts this instrument to specific API IDs.
	// If empty, all APIs are included.
	APIIDs []string `json:"api_ids,omitempty"`
	// Methods restricts this instrument to specific HTTP methods.
	// If empty, all methods are included.
	Methods []string `json:"methods,omitempty"`
	// StatusCodes restricts this instrument to specific status code patterns.
	// Supports exact codes ("200") and class patterns ("2xx", "5xx").
	// If empty, all status codes are included.
	StatusCodes []string `json:"status_codes,omitempty"`
}
