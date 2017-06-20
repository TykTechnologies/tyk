// Package nrlogrus forwards go-agent log messages to logrus.  If you are using
// logrus for your application and would like the go-agent log messages to end
// up in the same place, modify your config as follows:
//
//    cfg.Logger = nrlogrus.StandardLogger()
//
// Only logrus' StandardLogger is supported since there is no method (as of July
// 2016) to get the level of a logrus.Logger. See
// https://github.com/Sirupsen/logrus/issues/241
package nrlogrus

import (
	"github.com/Sirupsen/logrus"
	newrelic "github.com/newrelic/go-agent"
	"github.com/newrelic/go-agent/internal"
)

func init() { internal.TrackUsage("integration", "logging", "logrus") }

type shim struct{ e *logrus.Entry }

func (s *shim) Error(msg string, c map[string]interface{}) {
	s.e.WithFields(c).Error(msg)
}
func (s *shim) Warn(msg string, c map[string]interface{}) {
	s.e.WithFields(c).Warn(msg)
}
func (s *shim) Info(msg string, c map[string]interface{}) {
	s.e.WithFields(c).Info(msg)
}
func (s *shim) Debug(msg string, c map[string]interface{}) {
	s.e.WithFields(c).Info(msg)
}
func (s *shim) DebugEnabled() bool {
	lvl := logrus.GetLevel()
	return lvl >= logrus.DebugLevel
}

// StandardLogger returns a newrelic.Logger which forwards agent log messages to
// the logrus package-level exported logger.
func StandardLogger() newrelic.Logger {
	return &shim{
		e: logrus.WithFields(logrus.Fields{
			"component": "newrelic",
		}),
	}
}
