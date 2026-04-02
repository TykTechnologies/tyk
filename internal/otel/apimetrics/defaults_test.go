package apimetrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultAPIMetrics_Count(t *testing.T) {
	defs := DefaultAPIMetrics()
	assert.Len(t, defs, 4, "expected exactly 4 default instruments")
}

func TestDefaultAPIMetrics_NoDuplicateNames(t *testing.T) {
	defs := DefaultAPIMetrics()
	names := make(map[string]bool, len(defs))
	for _, d := range defs {
		require.False(t, names[d.Name], "duplicate instrument name: %s", d.Name)
		names[d.Name] = true
	}
}

func TestDefaultAPIMetrics_AllDimensionsUnder10(t *testing.T) {
	defs := DefaultAPIMetrics()
	for _, d := range defs {
		assert.LessOrEqual(t, len(d.Dimensions), 10,
			"instrument %s has %d dimensions, exceeding N<=10 threshold", d.Name, len(d.Dimensions))
	}
}

func TestDefaultAPIMetrics_NoRouteOrApiNameOrOrgId(t *testing.T) {
	excludedKeys := map[string]bool{
		"listen_path": true,
		"endpoint":    true,
		"api_name":    true,
		"org_id":      true,
	}

	defs := DefaultAPIMetrics()
	for _, d := range defs {
		for _, dim := range d.Dimensions {
			assert.False(t, excludedKeys[dim.Key],
				"instrument %s should not have dimension key %q in defaults", d.Name, dim.Key)
		}
	}
}

func TestDefaultAPIMetrics_InstrumentTypes(t *testing.T) {
	defs := DefaultAPIMetrics()

	histograms := 0
	counters := 0
	for _, d := range defs {
		switch d.Type {
		case "histogram":
			histograms++
			assert.NotEmpty(t, d.HistogramSource,
				"histogram %s must have a histogram_source", d.Name)
		case "counter":
			counters++
			assert.Empty(t, d.HistogramSource,
				"counter %s must not have a histogram_source", d.Name)
		default:
			t.Errorf("unexpected instrument type %q for %s", d.Type, d.Name)
		}
	}

	assert.Equal(t, 3, histograms, "expected 3 histogram instruments")
	assert.Equal(t, 1, counters, "expected 1 counter instrument")
}

func TestDefaultAPIMetrics_HistogramSources(t *testing.T) {
	defs := DefaultAPIMetrics()
	sources := make(map[string]bool)
	for _, d := range defs {
		if d.Type == "histogram" {
			sources[d.HistogramSource] = true
		}
	}

	assert.True(t, sources["total"], "expected a histogram with source 'total'")
	assert.True(t, sources["gateway"], "expected a histogram with source 'gateway'")
	assert.True(t, sources["upstream"], "expected a histogram with source 'upstream'")
}
