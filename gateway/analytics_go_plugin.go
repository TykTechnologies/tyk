package gateway

import (
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/goplugin"
)

type GoAnalyticsPlugin struct {
	Path     string // path to .so file
	FuncName string // function symbol to look up
	handler  func(record *analytics.AnalyticsRecord)
	logger   *logrus.Entry
}

func (m *GoAnalyticsPlugin) loadAnalyticsPlugin() bool {
	m.logger = log.WithFields(logrus.Fields{
		"mwPath":       m.Path,
		"mwSymbolName": m.FuncName,
	})

	if m.handler != nil {
		m.logger.Info("Go Analytics Plugin is already initialized")
		return true
	}

	// try to load plugin
	var err error

	if m.handler, err = goplugin.GetAnalyticsHandler(m.Path, m.FuncName); err != nil {
		m.logger.WithError(err).Error("Could not load Go-plugin for analytics")
		return false
	}

	return true
}

func (m *GoAnalyticsPlugin) processRecord(record *analytics.AnalyticsRecord) (err error) {
	if m == nil {
		return errors.New("GoAnalyticsPlugin has nil value")
	}

	// make sure tyk recover in case Go-plugin function panics
	defer func() {

		if e := recover(); e != nil {
			err = fmt.Errorf("%v", errors.New(fmt.Sprint(err)))
			m.logger.WithError(err).Error("Recovered from panic while running Go-plugin middleware func")
		}

	}()
	// call Go-plugin function
	t1 := time.Now()
	m.handler(record)

	// calculate latency
	ms := DurationToMillisecond(time.Since(t1))
	m.logger.WithField("ms", ms).Debug("Go-plugin analytics record processing took")

	return nil
}
