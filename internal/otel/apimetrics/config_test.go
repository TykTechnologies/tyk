package apimetrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: STK-REQ-092, SYS-REQ-180, SW-REQ-167
// STK-REQ-092:STK-REQ-092-AC-01:acceptance
// STK-REQ-092:error_handling:negative
// SYS-REQ-180:error_handling:nominal
// SYS-REQ-180:error_handling:negative
// SW-REQ-167:nominal:nominal
// SW-REQ-167:boundary:nominal
// SW-REQ-167:error_handling:nominal
// SW-REQ-167:error_handling:negative
// SW-REQ-167:encoding_safety:nominal
// SW-REQ-167:determinism:nominal
func TestAPIMetricDefinitionsDecode(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		want      APIMetricDefinitions
		wantError bool
	}{
		{
			name:  "valid counter definition",
			value: `[{"name":"tyk.test.total","type":"counter","description":"test counter","dimensions":[{"source":"metadata","key":"method","label":"http.request.method","default":"GET"}],"filters":{"api_ids":["api-1"],"methods":["GET"],"status_codes":["2xx"]}}]`,
			want: APIMetricDefinitions{
				{
					Name:        "tyk.test.total",
					Type:        "counter",
					Description: "test counter",
					Dimensions: []DimensionDefinition{
						{
							Source:  "metadata",
							Key:     "method",
							Label:   "http.request.method",
							Default: "GET",
						},
					},
					Filters: &MetricFilters{
						APIIDs:      []string{"api-1"},
						Methods:     []string{"GET"},
						StatusCodes: []string{"2xx"},
					},
				},
			},
		},
		{
			name:  "valid histogram definition",
			value: `[{"name":"tyk.test.duration","type":"histogram","histogram_source":"gateway","histogram_buckets":[0.1,0.5],"dimensions":[]}]`,
			want: APIMetricDefinitions{
				{
					Name:             "tyk.test.duration",
					Type:             "histogram",
					HistogramSource:  "gateway",
					HistogramBuckets: []float64{0.1, 0.5},
					Dimensions:       []DimensionDefinition{},
				},
			},
		},
		{
			name:      "invalid json",
			value:     `[{"name":`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got APIMetricDefinitions
			err := got.Decode(tt.value)
			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
