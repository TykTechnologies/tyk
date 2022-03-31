package logger_test

import (
	"testing"

	"github.com/TykTechnologies/tyk/internal/logger"

	"go.uber.org/zap"
)

func TestLogger(t *testing.T) {
	defer logger.Sync()

	zap.L().Info("This is a zap log entry")
}
