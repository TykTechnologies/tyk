package abstractlogger

// LevelCheck is a simple helper function to check the logging level before invoking the logging backend
// This is a very helpful optimization because it can avoid calling into variadic functions of the logging backend of your choice.
// In case of logrus this makes for a 300x improvement in performance (time/op) on a missed log level.
// In case of zap this improves the performance (time/op) by at least 69x on a missed log level.
type LevelCheck struct {
	level Level
}

func NewLevelCheck (level Level) LevelCheck {
	return LevelCheck{
		level:level,
	}
}

// Level are all possible logging levels in increasing order, starting with DebugLevel
type Level int

const (
	DebugLevel Level = iota - 1
	InfoLevel
	WarnLevel
	ErrorLevel
	PanicLevel
	FatalLevel
)

// Check returns true if the supplied logging level should be logged.
// Because the logging levels are increasing this is a simple greater equals check.
func (l LevelCheck) Check(level Level) bool {
	return level >= l.level
}