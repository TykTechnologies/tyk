//go:build v52
// +build v52

package config

import (
	"github.com/TykTechnologies/tyk/internal/otel"
)

// Features contain all the config options that have been added in this
// version. It's embedded into the Config{} struct, so the data model can be
// extended but not modified.
type Features struct {
	// Section for configuring Opentelemetry
	OpenTelemetry otel.Config `json:"opentelemetry"`
}
