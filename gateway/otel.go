package gateway

import (
	oteltrace "github.com/TykTechnologies/opentelemetry/trace"
	"github.com/sirupsen/logrus"
)

func (gw *Gateway) initOtel() error {
	gwConfig := gw.GetConfig()
	traceProvider, err := oteltrace.NewProvider(gw.ctx, gwConfig.OpenTelemetry)
	if err != nil {
		mainLog.WithFields(logrus.Fields{
			"opentelemetry.exporter":           gwConfig.OpenTelemetry.Exporter,
			"opentelemetry.endpoint":           gwConfig.OpenTelemetry.Endpoint,
			"opentelemetry.connection_timeout": gwConfig.OpenTelemetry.ConnectionTimeout,
		}).Error("unable to initialize tracing provider:", err)
		return err
	}

	gw.TraceProvider = traceProvider
	mainLog.WithFields(logrus.Fields{
		"opentelemetry.exporter":           gwConfig.OpenTelemetry.Exporter,
		"opentelemetry.endpoint":           gwConfig.OpenTelemetry.Endpoint,
		"opentelemetry.connection_timeout": gwConfig.OpenTelemetry.ConnectionTimeout,
	}).Info("connected to tracing backend")
	return nil
}
