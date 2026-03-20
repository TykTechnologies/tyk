package apimetrics

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validCounterDef(name string) APIMetricDefinition {
	return APIMetricDefinition{
		Name: name,
		Type: "counter",
		Dimensions: []DimensionDefinition{
			{Source: "metadata", Key: "method"},
		},
	}
}

func validHistogramDef(name string) APIMetricDefinition {
	return APIMetricDefinition{
		Name:            name,
		Type:            "histogram",
		HistogramSource: "total",
		Dimensions: []DimensionDefinition{
			{Source: "metadata", Key: "method"},
		},
	}
}

func TestValidateDefinitions(t *testing.T) {
	tests := []struct {
		name      string
		defs      []APIMetricDefinition
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid counter",
			defs:    []APIMetricDefinition{validCounterDef("test.counter")},
			wantErr: false,
		},
		{
			name:    "valid histogram",
			defs:    []APIMetricDefinition{validHistogramDef("test.histogram")},
			wantErr: false,
		},
		{
			name: "empty name",
			defs: []APIMetricDefinition{
				{Name: "", Type: "counter", Dimensions: []DimensionDefinition{{Source: "metadata", Key: "method"}}},
			},
			wantErr:   true,
			errSubstr: "name is required",
		},
		{
			name: "bad type",
			defs: []APIMetricDefinition{
				{Name: "test", Type: "gauge", Dimensions: []DimensionDefinition{{Source: "metadata", Key: "method"}}},
			},
			wantErr:   true,
			errSubstr: "type must be",
		},
		{
			name: "histogram missing source",
			defs: []APIMetricDefinition{
				{Name: "test", Type: "histogram", Dimensions: []DimensionDefinition{{Source: "metadata", Key: "method"}}},
			},
			wantErr:   true,
			errSubstr: "histogram_source is required",
		},
		{
			name: "histogram bad source",
			defs: []APIMetricDefinition{
				{Name: "test", Type: "histogram", HistogramSource: "invalid", Dimensions: []DimensionDefinition{{Source: "metadata", Key: "method"}}},
			},
			wantErr:   true,
			errSubstr: "histogram_source must be",
		},
		{
			name: "counter with histogram_source",
			defs: []APIMetricDefinition{
				{Name: "test", Type: "counter", HistogramSource: "total", Dimensions: []DimensionDefinition{{Source: "metadata", Key: "method"}}},
			},
			wantErr:   true,
			errSubstr: "histogram_source must be empty for counter",
		},
		{
			name: "unknown metadata key",
			defs: []APIMetricDefinition{
				{Name: "test", Type: "counter", Dimensions: []DimensionDefinition{{Source: "metadata", Key: "unknown_field"}}},
			},
			wantErr:   true,
			errSubstr: "unknown metadata key",
		},
		{
			name: "unknown session key",
			defs: []APIMetricDefinition{
				{Name: "test", Type: "counter", Dimensions: []DimensionDefinition{{Source: "session", Key: "unknown_field"}}},
			},
			wantErr:   true,
			errSubstr: "unknown session key",
		},
		{
			name: "unknown dimension source",
			defs: []APIMetricDefinition{
				{Name: "test", Type: "counter", Dimensions: []DimensionDefinition{{Source: "unknown", Key: "foo"}}},
			},
			wantErr:   true,
			errSubstr: "source must be one of",
		},
		{
			name: "empty dimension key",
			defs: []APIMetricDefinition{
				{Name: "test", Type: "counter", Dimensions: []DimensionDefinition{{Source: "header", Key: ""}}},
			},
			wantErr:   true,
			errSubstr: "key is required",
		},
		{
			name: "duplicate names",
			defs: []APIMetricDefinition{
				validCounterDef("dup.name"),
				validCounterDef("dup.name"),
			},
			wantErr:   true,
			errSubstr: "duplicate metric name",
		},
		{
			name: "bad status code filter - non-3-digit number",
			defs: []APIMetricDefinition{
				{
					Name: "test", Type: "counter",
					Dimensions: []DimensionDefinition{{Source: "metadata", Key: "method"}},
					Filters:    &MetricFilters{StatusCodes: []string{"20"}},
				},
			},
			wantErr:   true,
			errSubstr: "invalid status_code filter",
		},
		{
			name: "bad status code filter - invalid class pattern",
			defs: []APIMetricDefinition{
				{
					Name: "test", Type: "counter",
					Dimensions: []DimensionDefinition{{Source: "metadata", Key: "method"}},
					Filters:    &MetricFilters{StatusCodes: []string{"6xx"}},
				},
			},
			wantErr:   true,
			errSubstr: "invalid status_code filter",
		},
		{
			name: "bad status code filter - random string",
			defs: []APIMetricDefinition{
				{
					Name: "test", Type: "counter",
					Dimensions: []DimensionDefinition{{Source: "metadata", Key: "method"}},
					Filters:    &MetricFilters{StatusCodes: []string{"abc"}},
				},
			},
			wantErr:   true,
			errSubstr: "invalid status_code filter",
		},
		{
			name: "valid status code patterns",
			defs: []APIMetricDefinition{
				{
					Name: "test", Type: "counter",
					Dimensions: []DimensionDefinition{{Source: "metadata", Key: "method"}},
					Filters:    &MetricFilters{StatusCodes: []string{"200", "404", "2xx", "5xx"}},
				},
			},
			wantErr: false,
		},
		{
			name: "header source accepts any key",
			defs: []APIMetricDefinition{
				{Name: "test", Type: "counter", Dimensions: []DimensionDefinition{{Source: "header", Key: "X-Custom-Whatever"}}},
			},
			wantErr: false,
		},
		{
			name: "context source accepts any key",
			defs: []APIMetricDefinition{
				{Name: "test", Type: "counter", Dimensions: []DimensionDefinition{{Source: "context", Key: "any_variable"}}},
			},
			wantErr: false,
		},
		{
			name: "response_header source accepts any key",
			defs: []APIMetricDefinition{
				{Name: "test", Type: "counter", Dimensions: []DimensionDefinition{{Source: "response_header", Key: "X-Upstream-Header"}}},
			},
			wantErr: false,
		},
		{
			name: "config_data source accepts any key",
			defs: []APIMetricDefinition{
				{Name: "test", Type: "counter", Dimensions: []DimensionDefinition{{Source: "config_data", Key: "environment"}}},
			},
			wantErr: false,
		},
		{
			name: "all valid metadata keys",
			defs: []APIMetricDefinition{
				{
					Name: "test", Type: "counter",
					Dimensions: []DimensionDefinition{
						{Source: "metadata", Key: "method"},
						{Source: "metadata", Key: "response_code"},
						{Source: "metadata", Key: "listen_path"},
						{Source: "metadata", Key: "api_id"},
						{Source: "metadata", Key: "api_name"},
						{Source: "metadata", Key: "org_id"},
						{Source: "metadata", Key: "response_flag"},
						{Source: "metadata", Key: "ip_address"},
						{Source: "metadata", Key: "api_version"},
						{Source: "metadata", Key: "host"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "all valid session keys",
			defs: []APIMetricDefinition{
				{
					Name: "test", Type: "counter",
					Dimensions: []DimensionDefinition{
						{Source: "session", Key: "api_key"},
						{Source: "session", Key: "oauth_id"},
						{Source: "session", Key: "alias"},
						{Source: "session", Key: "portal_app"},
						{Source: "session", Key: "portal_org"},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "empty definitions valid",
			defs:    []APIMetricDefinition{},
			wantErr: false,
		},
		{
			name: "histogram source total valid",
			defs: []APIMetricDefinition{
				{Name: "h1", Type: "histogram", HistogramSource: "total", Dimensions: []DimensionDefinition{{Source: "metadata", Key: "method"}}},
			},
			wantErr: false,
		},
		{
			name: "histogram source gateway valid",
			defs: []APIMetricDefinition{
				{Name: "h1", Type: "histogram", HistogramSource: "gateway", Dimensions: []DimensionDefinition{{Source: "metadata", Key: "method"}}},
			},
			wantErr: false,
		},
		{
			name: "histogram source upstream valid",
			defs: []APIMetricDefinition{
				{Name: "h1", Type: "histogram", HistogramSource: "upstream", Dimensions: []DimensionDefinition{{Source: "metadata", Key: "method"}}},
			},
			wantErr: false,
		},
		{
			name: "scheme metadata key valid",
			defs: []APIMetricDefinition{
				{Name: "test", Type: "counter", Dimensions: []DimensionDefinition{{Source: "metadata", Key: "scheme"}}},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateDefinitions(tt.defs)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateDefinitions_SessionOnHistogramWarns(t *testing.T) {
	defs := []APIMetricDefinition{
		{
			Name:            "hist.with.session",
			Type:            "histogram",
			HistogramSource: "total",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "method"},
				{Source: "session", Key: "api_key"},
				{Source: "session", Key: "oauth_id"},
			},
		},
	}

	warnings, err := ValidateDefinitions(defs)
	require.NoError(t, err)
	assert.Len(t, warnings, 2, "expected 2 session-on-histogram cardinality warnings")
	assert.Contains(t, warnings[0], "api_key")
	assert.Contains(t, warnings[0], "high cardinality")
	assert.Contains(t, warnings[1], "oauth_id")
	assert.Contains(t, warnings[1], "high cardinality")
}

func TestValidateDefinitions_SessionOnCounterNoWarning(t *testing.T) {
	defs := []APIMetricDefinition{
		{
			Name: "counter.with.session",
			Type: "counter",
			Dimensions: []DimensionDefinition{
				{Source: "session", Key: "api_key"},
			},
		},
	}

	warnings, err := ValidateDefinitions(defs)
	require.NoError(t, err)
	assert.Empty(t, warnings, "counter with session dimensions should not warn")
}

func TestValidateDefinitions_ExceedsDimensionThreshold(t *testing.T) {
	dims := make([]DimensionDefinition, 11)
	for i := range dims {
		dims[i] = DimensionDefinition{Source: "header", Key: fmt.Sprintf("X-Dim-%d", i)}
	}

	defs := []APIMetricDefinition{
		{Name: "big.counter", Type: "counter", Dimensions: dims},
	}

	warnings, err := ValidateDefinitions(defs)
	require.NoError(t, err)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "exceeding recommended N<=10")
	assert.Contains(t, warnings[0], "11 dimensions")
}
