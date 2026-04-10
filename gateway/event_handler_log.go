package gateway

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/sirupsen/logrus"
)

// LogEventMessage is an interface that provides a method for formatting log events into a string with a given prefix.
type LogEventMessage interface {
	LogMessage(prefix string) string
}

// LogMessageEventHandler is a sample Event Handler
type LogMessageEventHandler struct {
	conf   apidef.LogEventHandlerConf
	logger *logrus.Logger
	Gw     *Gateway `json:"-"`
}

// Init initializes the LogMessageEventHandler instance with the given configuration.
func (l *LogMessageEventHandler) Init(handlerConf any) error {
	var err error
	if err = l.conf.Scan(handlerConf); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "log_event_handler",
		}).Error("Problem getting configuration, skipping. ", err)
		return err
	}

	if l.conf.Disabled {
		log.WithFields(logrus.Fields{
			"prefix": "log_event_handler",
		}).Infof("skipping disabled log event handler with prefix %s", l.conf.Prefix)
		return ErrEventHandlerDisabled
	}

	l.logger = log
	return nil
}

// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (l *LogMessageEventHandler) HandleEvent(em config.EventMessage) {
	logMsg := l.conf.Prefix + ":" + string(em.Type)

	logEventMessage, ok := em.Meta.(LogEventMessage)
	if ok {
		logMsg = logEventMessage.LogMessage(logMsg)
	}

	l.logger.Warning(logMsg)
}
