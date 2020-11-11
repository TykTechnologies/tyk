package osin

// Logger creates a formatted log event.
// NOTE: Log is meant for internal use only and may contain sensitive info.
type Logger interface {
	Printf(format string, v ...interface{})
}

type LoggerDefault struct {
}

func (l LoggerDefault) Printf(format string, v ...interface{}) {
}
