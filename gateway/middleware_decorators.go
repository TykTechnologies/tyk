package gateway

import (
	"github.com/TykTechnologies/tyk/user"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
)

var _ TykResponseHandler = (*logDecorator)(nil)

type (
	logDecorator struct {
		TykResponseHandler
	}

	tykResponseDecorator func(origin TykResponseHandler) TykResponseHandler
)

func withLogger(
	logger *logrus.Entry,
) tykResponseDecorator {

	return func(origin TykResponseHandler) TykResponseHandler {
		origin.setLogger(logger.WithFields(logrus.Fields{
			"mw":   origin.Name(),
			"type": "response",
		}))

		return &logDecorator{
			TykResponseHandler: origin,
		}
	}
}

func decorateReqMiddlewares(origin TykResponseHandler, decorators ...tykResponseDecorator) TykResponseHandler {
	for _, fn := range decorators {
		origin = fn(origin)
	}
	return origin
}

func makeDefaultDecorator(logger *logrus.Entry) tykResponseDecorator {
	return func(origin TykResponseHandler) TykResponseHandler {
		return decorateReqMiddlewares(origin, withLogger(logger))
	}
}

func (d *logDecorator) HandleResponse(
	writer http.ResponseWriter,
	response *http.Response,
	request *http.Request,
	state *user.SessionState,
) error {

	start := time.Now()
	logger := d.logger()
	if logger.Logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithField("ts", start.UnixNano()).Debug("Started")
	}

	if err := d.TykResponseHandler.HandleResponse(writer, response, request, state); err != nil {
		d.logger().WithField("ns", time.Since(start).Nanoseconds()).WithError(err).Error("Failed to process response")
		return err
	}

	if logger.Logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithField("ns", time.Since(start).Nanoseconds()).Debug("Finished")
	}

	return nil
}
