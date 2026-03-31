package apimetrics

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tykmetric "github.com/TykTechnologies/opentelemetry/metric"
)

// noopProvider creates a disabled metric provider suitable for unit tests.
// The noop provider returns nil-safe counters and histograms.
func noopProvider(t *testing.T) tykmetric.Provider {
	t.Helper()
	provider, err := tykmetric.NewProvider(
		tykmetric.WithContext(context.Background()),
	)
	require.NoError(t, err)
	return provider
}

func TestNewInstrumentRegistry_DefaultInstruments(t *testing.T) {
	provider := noopProvider(t)
	defs := DefaultAPIMetrics()

	reg, err := NewInstrumentRegistry(provider, defs)
	require.NoError(t, err)
	assert.Len(t, reg.instruments, 4, "expected 4 default instruments")

	// Default instruments do not use session source.
	assert.False(t, reg.NeedsSession(), "defaults do not use session source")
	// Default instruments only use metadata and session, not context, response_header, or config_data.
	assert.False(t, reg.NeedsContext(), "defaults do not use context source")
	assert.False(t, reg.NeedsResponse(), "defaults do not use response_header source")
	assert.False(t, reg.NeedsConfigData(), "defaults do not use config_data source")
}

func TestNewInstrumentRegistry_ValidationErrors(t *testing.T) {
	provider := noopProvider(t)

	// Missing name triggers validation error.
	_, err := NewInstrumentRegistry(provider, []APIMetricDefinition{
		{Name: "", Type: "counter"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestNewInstrumentRegistry_NeedsSession(t *testing.T) {
	provider := noopProvider(t)

	t.Run("true when session source used", func(t *testing.T) {
		defs := []APIMetricDefinition{
			{
				Name: "test.counter",
				Type: "counter",
				Dimensions: []DimensionDefinition{
					{Source: "session", Key: "api_key", Label: "key"},
				},
			},
		}
		reg, err := NewInstrumentRegistry(provider, defs)
		require.NoError(t, err)
		assert.True(t, reg.NeedsSession())
	})

	t.Run("false when no session source", func(t *testing.T) {
		defs := []APIMetricDefinition{
			{
				Name: "test.counter",
				Type: "counter",
				Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method"},
				},
			},
		}
		reg, err := NewInstrumentRegistry(provider, defs)
		require.NoError(t, err)
		assert.False(t, reg.NeedsSession())
	})
}

func TestNewInstrumentRegistry_NeedsContext(t *testing.T) {
	provider := noopProvider(t)

	t.Run("true when context source used", func(t *testing.T) {
		defs := []APIMetricDefinition{
			{
				Name: "test.counter",
				Type: "counter",
				Dimensions: []DimensionDefinition{
					{Source: "context", Key: "tier", Label: "tier"},
				},
			},
		}
		reg, err := NewInstrumentRegistry(provider, defs)
		require.NoError(t, err)
		assert.True(t, reg.NeedsContext())
	})

	t.Run("false when no context source", func(t *testing.T) {
		defs := []APIMetricDefinition{
			{
				Name: "test.counter",
				Type: "counter",
				Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method"},
				},
			},
		}
		reg, err := NewInstrumentRegistry(provider, defs)
		require.NoError(t, err)
		assert.False(t, reg.NeedsContext())
	})
}

func TestNewInstrumentRegistry_NeedsResponse(t *testing.T) {
	provider := noopProvider(t)

	t.Run("true when response_header source used", func(t *testing.T) {
		defs := []APIMetricDefinition{
			{
				Name: "test.counter",
				Type: "counter",
				Dimensions: []DimensionDefinition{
					{Source: "response_header", Key: "X-Cache", Label: "cache"},
				},
			},
		}
		reg, err := NewInstrumentRegistry(provider, defs)
		require.NoError(t, err)
		assert.True(t, reg.NeedsResponse())
	})

	t.Run("false when no response_header source", func(t *testing.T) {
		defs := []APIMetricDefinition{
			{
				Name: "test.counter",
				Type: "counter",
				Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method"},
				},
			},
		}
		reg, err := NewInstrumentRegistry(provider, defs)
		require.NoError(t, err)
		assert.False(t, reg.NeedsResponse())
	})
}

func TestNewInstrumentRegistry_CounterAndHistogram(t *testing.T) {
	provider := noopProvider(t)

	defs := []APIMetricDefinition{
		{
			Name: "test.counter",
			Type: "counter",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "method"},
			},
		},
		{
			Name:            "test.histogram",
			Type:            "histogram",
			HistogramSource: "total",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "api_id"},
			},
		},
	}

	reg, err := NewInstrumentRegistry(provider, defs)
	require.NoError(t, err)
	require.Len(t, reg.instruments, 2)

	assert.Equal(t, "counter", reg.instruments[0].Type)
	assert.NotNil(t, reg.instruments[0].Counter)
	assert.Nil(t, reg.instruments[0].Histogram)

	assert.Equal(t, "histogram", reg.instruments[1].Type)
	assert.Nil(t, reg.instruments[1].Counter)
	assert.NotNil(t, reg.instruments[1].Histogram)
}

func TestNewInstrumentRegistry_WithFilters(t *testing.T) {
	provider := noopProvider(t)

	defs := []APIMetricDefinition{
		{
			Name: "filtered.counter",
			Type: "counter",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "method"},
			},
			Filters: &MetricFilters{
				APIIDs:  []string{"api-1"},
				Methods: []string{"GET"},
			},
		},
		{
			Name: "unfiltered.counter",
			Type: "counter",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "method"},
			},
		},
	}

	reg, err := NewInstrumentRegistry(provider, defs)
	require.NoError(t, err)
	require.Len(t, reg.instruments, 2)

	assert.NotNil(t, reg.instruments[0].Filter, "first instrument should have a filter")
	assert.Nil(t, reg.instruments[1].Filter, "second instrument should have no filter")
}

func TestNewInstrumentRegistry_NeedsMCP(t *testing.T) {
	provider := noopProvider(t)

	t.Run("true when mcp metadata key used", func(t *testing.T) {
		defs := []APIMetricDefinition{
			{
				Name: "test.counter",
				Type: "counter",
				Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "mcp_method"},
				},
			},
		}
		reg, err := NewInstrumentRegistry(provider, defs)
		require.NoError(t, err)
		assert.True(t, reg.NeedsMCP())
	})

	t.Run("false when no mcp metadata key", func(t *testing.T) {
		defs := []APIMetricDefinition{
			{
				Name: "test.counter",
				Type: "counter",
				Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method"},
				},
			},
		}
		reg, err := NewInstrumentRegistry(provider, defs)
		require.NoError(t, err)
		assert.False(t, reg.NeedsMCP())
	})

	t.Run("true across multiple instruments", func(t *testing.T) {
		defs := []APIMetricDefinition{
			{
				Name: "test.counter",
				Type: "counter",
				Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method"},
				},
			},
			{
				Name: "test.counter2",
				Type: "counter",
				Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "mcp_primitive_type"},
				},
			},
		}
		reg, err := NewInstrumentRegistry(provider, defs)
		require.NoError(t, err)
		assert.True(t, reg.NeedsMCP())
	})

	t.Run("false for default metrics", func(t *testing.T) {
		defs := DefaultAPIMetrics()
		reg, err := NewInstrumentRegistry(provider, defs)
		require.NoError(t, err)
		assert.False(t, reg.NeedsMCP(), "default metrics should not need MCP")
	})
}

func TestNewInstrumentRegistry_NeedsConfigData(t *testing.T) {
	provider := noopProvider(t)

	t.Run("true when config_data source used", func(t *testing.T) {
		defs := []APIMetricDefinition{
			{
				Name: "test.counter",
				Type: "counter",
				Dimensions: []DimensionDefinition{
					{Source: "config_data", Key: "environment", Label: "env"},
				},
			},
		}
		reg, err := NewInstrumentRegistry(provider, defs)
		require.NoError(t, err)
		assert.True(t, reg.NeedsConfigData())
	})

	t.Run("false when no config_data source", func(t *testing.T) {
		defs := []APIMetricDefinition{
			{
				Name: "test.counter",
				Type: "counter",
				Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method"},
				},
			},
		}
		reg, err := NewInstrumentRegistry(provider, defs)
		require.NoError(t, err)
		assert.False(t, reg.NeedsConfigData())
	})

	t.Run("false for default metrics", func(t *testing.T) {
		defs := DefaultAPIMetrics()
		reg, err := NewInstrumentRegistry(provider, defs)
		require.NoError(t, err)
		assert.False(t, reg.NeedsConfigData(), "default metrics should not need config_data")
	})
}

func TestNewInstrumentRegistry_MultipleSourceFlags(t *testing.T) {
	provider := noopProvider(t)

	defs := []APIMetricDefinition{
		{
			Name: "multi.source",
			Type: "counter",
			Dimensions: []DimensionDefinition{
				{Source: "session", Key: "api_key", Label: "key"},
				{Source: "context", Key: "tier", Label: "tier"},
				{Source: "response_header", Key: "X-Cache", Label: "cache"},
				{Source: "config_data", Key: "environment", Label: "env"},
			},
		},
	}

	reg, err := NewInstrumentRegistry(provider, defs)
	require.NoError(t, err)
	assert.True(t, reg.NeedsSession())
	assert.True(t, reg.NeedsContext())
	assert.True(t, reg.NeedsResponse())
	assert.True(t, reg.NeedsConfigData())
}
