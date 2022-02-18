package gateway

import (
	"fmt"
	"github.com/TykTechnologies/tyk/analytics"
	"github.com/TykTechnologies/tyk/goplugin"
	"github.com/sirupsen/logrus"
)

type GoAnalyticsPlugin struct {
	Path     string // path to .so file
	FuncName string // function symbol to look up
	handler  func(record *analytics.Record)
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

func (m *GoAnalyticsPlugin) processRecord(record *analytics.Record) (err error) {
	// make sure tyk recover in case Go-plugin function panics
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
			m.logger.WithError(err).Error("Recovered from panic while running Go-plugin middleware func")
		}
	}()

	m.handler(record)

	return nil
}
