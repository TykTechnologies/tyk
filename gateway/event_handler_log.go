package gateway

import (
	"fmt"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/sirupsen/logrus"
)

const (
	// EH_LogHandler is an alias maintained for backwards compatibility.
	// It is used to register log handler on an event.
	EH_LogHandler = event.LogHandler
)

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

	// We can handle specific event types easily
	if em.Type == EventQuotaExceeded {
		msgConf, ok := em.Meta.(EventKeyFailureMeta)
		if ok {
			logMsg = logMsg + ":" + msgConf.Key + ":" + msgConf.Origin + ":" + msgConf.Path
		}
	}

	if em.Type == EventBreakerTriggered {
		msgConf, ok := em.Meta.(EventCurcuitBreakerMeta)
		if ok {
			logMsg = logMsg + ":" + msgConf.APIID + ":" + msgConf.Path + ": [STATUS] " + fmt.Sprint(msgConf.CircuitEvent)
		}
	}

	l.logger.Warning(logMsg)
}
