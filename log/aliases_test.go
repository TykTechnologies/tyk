package log_test

import (
	"testing"

	"github.com/TykTechnologies/tyk/log"
)

func TestAliases(t *testing.T) {
	var (
		_ log.Level = log.ErrorLevel
	)

	logger := log.Get()
	logger.Info("Hello from test")
}
