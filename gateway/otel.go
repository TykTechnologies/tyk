package gateway

import (
	tyktrace "github.com/TykTechnologies/opentelemetry/trace"
	"github.com/sirupsen/logrus"
)

func (gw *Gateway) InitOpenTelemetry() {
	gwConfig := gw.GetConfig()

	traceLogger := mainLog.WithFields(logrus.Fields{
		"exporter":           gwConfig.OpenTelemetry.Exporter,
		"endpoint":           gwConfig.OpenTelemetry.Endpoint,
		"connection_timeout": gwConfig.OpenTelemetry.ConnectionTimeout,
	})

	var errOtel error
	gw.TraceProvider, errOtel = tyktrace.NewProvider(
		tyktrace.WithContext(gw.ctx),
		tyktrace.WithConfig(&gwConfig.OpenTelemetry),
		tyktrace.WithLogger(traceLogger),
	)

	if errOtel != nil {
		mainLog.Errorf("Initializing OpenTelemetry %s", errOtel)
	}
}
