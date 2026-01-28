//go:build !ee && !dev

// Provides getStreamingMiddleware
package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/ee"
)

const (
	MessageStreamingOnlySupportedInEE = "streaming is supported only in Tyk Enterprise Edition"
)

func getStreamingMiddleware(base *BaseMiddleware) TykMiddleware {
	return &dummyStreamingMiddleware{base}
}

type dummyStreamingMiddleware struct {
	*BaseMiddleware
}

func (d *dummyStreamingMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	failHttpCode := http.StatusForbidden
	d.Logger().WithField("status_code", failHttpCode).Errorf("Error: %s", MessageStreamingOnlySupportedInEE)
	return ee.ErrActionNotAllowed, failHttpCode
}

func (d *dummyStreamingMiddleware) EnabledForSpec() bool {
	streamingConfig := d.Gw.GetConfig().Streaming

	if streamingConfig.Enabled && d.Spec.isStreamingAPI() {
		d.Logger().Warnf("Warning: %s", MessageStreamingOnlySupportedInEE)
		return true
	}

	return false
}

func (d *dummyStreamingMiddleware) Name() string {
	return "StreamingMiddleware"
}
