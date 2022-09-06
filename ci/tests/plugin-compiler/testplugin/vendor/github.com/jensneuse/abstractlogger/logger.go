package abstractlogger

// Logger is the interface to abstract away a general purpose logger
type Logger interface {
	DebugLogger
	InfoLogger
	WarnLogger
	ErrorLogger
	FatalLogger
	PanicLogger
	LevelLogger(level Level) LevelLogger
}

type LevelLogger interface {
	Println(v ...interface{})
	Printf(format string, v ...interface{})
}

// NoopLogger satisfies the Logger interface while doing nothing
var NoopLogger Logger = Noop{}

type DebugLogger interface {
	Debug(msg string,fields ...Field)
}

type ErrorLogger interface {
	Error(msg string,fields ...Field)
}

type FatalLogger interface {
	Fatal(msg string,fields ...Field)
}

type InfoLogger interface {
	Info(msg string,fields ...Field)
}

type PanicLogger interface {
	Panic(msg string,fields ...Field)
}

type WarnLogger interface {
	Warn(msg string,fields ...Field)
}

type LevelNoop struct {}

func (_ LevelNoop) Println(v ...interface{}) {
	
}

func (_ LevelNoop) Printf(format string, v ...interface{}) {
	
}

type Noop struct {}

func (_ Noop) LevelLogger(level Level) LevelLogger {
	return LevelNoop{}
}

func (_ Noop) Debug(msg string, fields ...Field) {
	
}

func (_ Noop) Info(msg string, fields ...Field) {
	
}

func (_ Noop) Warn(msg string, fields ...Field) {
	
}

func (_ Noop) Error(msg string, fields ...Field) {
	
}

func (_ Noop) Fatal(msg string, fields ...Field) {
	
}

func (_ Noop) Panic(msg string, fields ...Field) {
	
}

