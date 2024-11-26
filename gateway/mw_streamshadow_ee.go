//go:build ee || dev

package gateway

import (
	"github.com/TykTechnologies/tyk/ee/middleware/streamshadow"
	"github.com/sirupsen/logrus"
)

func getStreamShadowMiddleware(baseMid *BaseTykResponseHandler, logger *logrus.Entry) TykResponseHandler {
	streamShadowMw := streamshadow.NewMiddleware(baseMid.Gw, baseMid.Spec, baseMid.Spec.APIDefinition, logger)
	return WrapResponseHandler(baseMid, streamShadowMw)
}
