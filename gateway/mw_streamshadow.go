//go:build !ee && !dev

package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/user"
	"github.com/sirupsen/logrus"
)

const (
	MessageStreamShadowOnlySupportedInEE = "stream shadow is supported only in Tyk Enterprise Edition"
)

func getStreamShadowMiddleware(base *BaseTykResponseHandler, logger *logrus.Entry) TykResponseHandler {
	return &dummyStreamShadowMiddleware{base}
}

type dummyStreamShadowMiddleware struct {
	*BaseTykResponseHandler
}

func (d *dummyStreamShadowMiddleware) HandleResponse(w http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	return nil
}

func (d *dummyStreamShadowMiddleware) HandleError(rw http.ResponseWriter, req *http.Request) {
	// noop
}

func (d *dummyStreamShadowMiddleware) Name() string {
	return "StreamShadowResponseMiddleware"
}

func (d *dummyStreamShadowMiddleware) Enabled() bool {
	return false
}

func (d *dummyStreamShadowMiddleware) Base() *BaseTykResponseHandler {
	return d.BaseTykResponseHandler
}
