package apimetrics

import (
	"fmt"
	"strings"

	logger "github.com/sirupsen/logrus"

	tykmetric "github.com/TykTechnologies/opentelemetry/metric"
)

// MetricInstrument holds a compiled instrument with its builder, filter, and OTel handle.
type MetricInstrument struct {
	Name            string
	Type            string
	HistogramSource string
	Builder         *DimensionBuilder
	Filter          *CompiledFilter
	Counter         *tykmetric.Counter
	Histogram       *tykmetric.Histogram
}

// InstrumentRegistry holds all compiled metric instruments and pre-computed flags.
type InstrumentRegistry struct {
	instruments     []*MetricInstrument
	needsSession    bool // true if any instrument uses source:"session"
	needsContext    bool // true if any instrument uses source:"context"
	needsResponse   bool // true if any instrument uses source:"response_header"
	needsMCP        bool // true if any instrument uses source:"metadata" with key prefix "mcp_"
	needsConfigData bool // true if any instrument uses source:"config_data"
}

// NewInstrumentRegistry validates definitions, compiles builders and filters,
// and creates OTel instruments from the provider.
func NewInstrumentRegistry(provider tykmetric.Provider, defs []APIMetricDefinition) (*InstrumentRegistry, error) {
	warnings, err := ValidateDefinitions(defs)
	for _, w := range warnings {
		logger.Warn(w)
	}
	if err != nil {
		return nil, err
	}

	reg := &InstrumentRegistry{}

	for _, def := range defs {
		// Pre-compute source flags by scanning dimensions.
		for _, dim := range def.Dimensions {
			switch dim.Source {
			case "session":
				reg.needsSession = true
			case "context":
				reg.needsContext = true
			case "response_header":
				reg.needsResponse = true
			case "config_data":
				reg.needsConfigData = true
			case "metadata":
				if strings.HasPrefix(dim.Key, "mcp_") {
					reg.needsMCP = true
				}
			}
		}

		builder, err := NewDimensionBuilder(def.Dimensions)
		if err != nil {
			return nil, fmt.Errorf("api_metrics[%s]: %w", def.Name, err)
		}

		filter := CompileFilter(def.Filters)

		inst := &MetricInstrument{
			Name:            def.Name,
			Type:            def.Type,
			HistogramSource: def.HistogramSource,
			Builder:         builder,
			Filter:          filter,
		}

		switch def.Type {
		case "counter":
			c, err := provider.NewCounter(def.Name, def.Description, "1")
			if err != nil {
				return nil, fmt.Errorf("api_metrics[%s]: creating counter: %w", def.Name, err)
			}
			inst.Counter = c

		case "histogram":
			buckets := def.HistogramBuckets
			if len(buckets) == 0 {
				buckets = tykmetric.DefaultLatencyBucketsSeconds
			}
			h, err := provider.NewHistogram(def.Name, def.Description, "s", buckets)
			if err != nil {
				return nil, fmt.Errorf("api_metrics[%s]: creating histogram: %w", def.Name, err)
			}
			inst.Histogram = h
		}

		reg.instruments = append(reg.instruments, inst)
	}

	return reg, nil
}

// NeedsSession returns true if any instrument uses session dimensions.
func (r *InstrumentRegistry) NeedsSession() bool { return r.needsSession }

// NeedsContext returns true if any instrument uses context dimensions.
func (r *InstrumentRegistry) NeedsContext() bool { return r.needsContext }

// NeedsResponse returns true if any instrument uses response_header dimensions.
func (r *InstrumentRegistry) NeedsResponse() bool { return r.needsResponse }

// NeedsMCP returns true if any instrument uses MCP metadata dimensions (key prefix "mcp_").
func (r *InstrumentRegistry) NeedsMCP() bool { return r.needsMCP }

// NeedsConfigData returns true if any instrument uses config_data dimensions.
func (r *InstrumentRegistry) NeedsConfigData() bool { return r.needsConfigData }
