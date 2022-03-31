package logger

import (
	"os"
	"strings"

	"go.uber.org/zap"
)

// This package provides a logger for application use.
//
// main() - or equivalent location:
//
// ```
// import (
// 	"github.com/TykTechnologies/internal/logger"
// )
//
// func main() {
// 	defer logger.Sync()
// }
// ```
//
// After this setup, import and use `go.uber.org/zap` as
// one does. The default logger is replaced in init().

var globalLogger *zap.Logger

func init() {
	var config zap.Config

	env := os.Getenv("ENVIRONMENT")
	level := strings.ToLower(os.Getenv("TYK_LOGLEVEL"))

	// set logger config based on empty/dev/
	if env == "" || env == "development" || level == "debug" {
		config = zap.NewDevelopmentConfig()
	} else {
		config = zap.NewProductionConfig()
	}

	// set log level based on TYK_LOGLEVEL
	switch level {
	case "error":
		config.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	case "warn":
		config.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	default:
		// default log level is info
	}

	logger, err := config.Build()
	if err != nil {
		panic(err)
	}
	zap.ReplaceGlobals(logger)
	globalLogger = logger

	envConfig := "production"
	if config.Development {
		envConfig = "development"
	}
	logger.Sugar().Infof("Created %s zap logger with log level %q", envConfig, config.Level.Level().CapitalString())
}

// We need to expose this so we can flush anything
// left in the loggers buffers to console out
func Sync() error {
	return globalLogger.Sync()
}
