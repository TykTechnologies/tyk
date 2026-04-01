package apimetrics

import (
	"fmt"
	"regexp"
	"strconv"
)

// validMetadataKeys is derived from metadataExtractors to keep a single source of truth.
var validMetadataKeys = func() map[string]bool {
	m := make(map[string]bool, len(metadataExtractors))
	for k := range metadataExtractors {
		m[k] = true
	}
	return m
}()

// validSessionKeys is derived from sessionExtractors to keep a single source of truth.
var validSessionKeys = func() map[string]bool {
	m := make(map[string]bool, len(sessionExtractors))
	for k := range sessionExtractors {
		m[k] = true
	}
	return m
}()

// validDimensionSources is the set of allowed dimension sources.
var validDimensionSources = map[string]bool{
	"metadata":        true,
	"session":         true,
	"header":          true,
	"context":         true,
	"response_header": true,
	"config_data":     true,
}

// statusCodeClassPattern matches class patterns like "2xx", "4xx", "5xx".
var statusCodeClassPattern = regexp.MustCompile(`^[1-5]xx$`)

// ValidateDefinitions validates all API metric definitions at startup.
// Returns any warnings (non-fatal) and the first error encountered.
// Warnings include high-cardinality risks and threshold violations.
func ValidateDefinitions(defs []APIMetricDefinition) (warnings []string, err error) {
	names := make(map[string]bool, len(defs))

	for i, def := range defs {
		prefix := fmt.Sprintf("api_metrics[%d]", i)

		if def.Name == "" {
			return warnings, fmt.Errorf("%s: name is required", prefix)
		}

		prefix = fmt.Sprintf("api_metrics[%q]", def.Name)

		if names[def.Name] {
			return warnings, fmt.Errorf("%s: duplicate metric name", prefix)
		}
		names[def.Name] = true

		if def.Type != "counter" && def.Type != "histogram" {
			return warnings, fmt.Errorf("%s: type must be \"counter\" or \"histogram\", got %q", prefix, def.Type)
		}

		if def.Type == "histogram" {
			if def.HistogramSource == "" {
				return warnings, fmt.Errorf("%s: histogram_source is required for histogram type", prefix)
			}
			if def.HistogramSource != "total" && def.HistogramSource != "gateway" && def.HistogramSource != "upstream" {
				return warnings, fmt.Errorf("%s: histogram_source must be \"total\", \"gateway\", or \"upstream\", got %q", prefix, def.HistogramSource)
			}
		}

		if def.Type == "counter" && def.HistogramSource != "" {
			return warnings, fmt.Errorf("%s: histogram_source must be empty for counter type", prefix)
		}

		for j, dim := range def.Dimensions {
			dimPrefix := fmt.Sprintf("%s.dimensions[%d]", prefix, j)

			if !validDimensionSources[dim.Source] {
				return warnings, fmt.Errorf("%s: source must be one of metadata, session, header, context, response_header, config_data; got %q", dimPrefix, dim.Source)
			}

			if dim.Key == "" {
				return warnings, fmt.Errorf("%s: key is required", dimPrefix)
			}

			switch dim.Source {
			case "metadata":
				if !validMetadataKeys[dim.Key] {
					return warnings, fmt.Errorf("%s: unknown metadata key %q", dimPrefix, dim.Key)
				}
			case "session":
				if !validSessionKeys[dim.Key] {
					return warnings, fmt.Errorf("%s: unknown session key %q", dimPrefix, dim.Key)
				}
			}
			// header, context, response_header, config_data accept any non-empty key (already checked above).
		}

		if len(def.Dimensions) > 10 {
			warnings = append(warnings, fmt.Sprintf("%s: has %d dimensions, exceeding recommended N<=10 threshold", prefix, len(def.Dimensions)))
		}

		// Warn about high-cardinality session dimensions on histograms.
		if def.Type == "histogram" {
			for _, dim := range def.Dimensions {
				if dim.Source == "session" {
					warnings = append(warnings, fmt.Sprintf("%s: session dimension %q on histogram has high cardinality risk", prefix, dim.Key))
				}
			}
		}

		if def.Filters != nil {
			for _, sc := range def.Filters.StatusCodes {
				if _, err := strconv.Atoi(sc); err != nil {
					if !statusCodeClassPattern.MatchString(sc) {
						return warnings, fmt.Errorf("%s: invalid status_code filter %q (must be exact 3-digit code or class pattern like \"2xx\")", prefix, sc)
					}
				} else if len(sc) != 3 {
					return warnings, fmt.Errorf("%s: invalid status_code filter %q (must be a 3-digit code)", prefix, sc)
				}
			}
		}
	}

	return warnings, nil
}
