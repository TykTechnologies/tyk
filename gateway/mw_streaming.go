//go:build !ee && !dev

// Provides getStreamingMiddleware
package gateway

import (
	"net/http"
)

func getStreamingMiddleware(base *BaseMiddleware) TykMiddleware {
	return &dummyStreamingMiddleware{base}
}

type dummyStreamingMiddleware struct {
	*BaseMiddleware
}

func (d *dummyStreamingMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	return nil, http.StatusOK
}

func (d *dummyStreamingMiddleware) EnabledForSpec() bool {
	streamingConfig := d.Gw.GetConfig().Streaming

	if streamingConfig.Enabled {
		d.Logger().Error("Error: Streaming is supported only in Tyk Enterprise Edition")
	}

	return false
}

func (d *dummyStreamingMiddleware) Name() string {
	return "StreamingMiddleware"
}
