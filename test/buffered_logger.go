package test

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Implements a buffered logger to be used in tests in replacement of the main logger.
// It stores the logs in memory and allows to retrieve them.

// BufferedLog is the struct that holds the log entry.
type BufferedLog struct {
	Message string       `json:"message"`
	Time    time.Time    `json:"time"`
	Level   logrus.Level `json:"level"`
}

// BufferingFormatter is the struct that holds the buffer of the logs.
type BufferingFormatter struct {
	bufferMutex sync.Mutex
	buffer      []*BufferedLog
}

// Format is the method that stores the log entry in the buffer.
func (f *BufferingFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	f.bufferMutex.Lock()
	defer f.bufferMutex.Unlock()

	bl := &BufferedLog{
		Message: entry.Message,
		Time:    entry.Time.UTC(),
		Level:   entry.Level,
	}

	f.buffer = append(f.buffer, bl)
	return nil, nil
}

// BufferedLogger is the struct that holds the logger and the buffer.
type BufferedLogger struct {
	*logrus.Logger
	bufferingFormatter *BufferingFormatter
}

// GetLogs returns the logs that are stored in the buffer.
func (bl *BufferedLogger) GetLogs(Level logrus.Level) []*BufferedLog {
	bl.bufferingFormatter.bufferMutex.Lock()
	defer bl.bufferingFormatter.bufferMutex.Unlock()

	logs := make([]*BufferedLog, 0)
	for _, log := range bl.bufferingFormatter.buffer {
		if log.Level == Level {
			logs = append(logs, log)
		}
	}
	return logs
}

// ClearLogs clears the logs from the buffer.
// IMPORTANT: Must be called before each test iteration.
func (bl *BufferedLogger) ClearLogs() {
	bl.bufferingFormatter.bufferMutex.Lock()
	defer bl.bufferingFormatter.bufferMutex.Unlock()
	bl.bufferingFormatter.buffer = make([]*BufferedLog, 0)
}

var buflogger *BufferedLogger

// NewBufferingLogger creates a new buffered logger.
func NewBufferingLogger() *BufferedLogger {
	if buflogger != nil {
		return buflogger
	}

	bufferingFormatter := &BufferingFormatter{buffer: make([]*BufferedLog, 0)}
	logger := logrus.New()
	logger.Level = logrus.DebugLevel
	logger.Formatter = bufferingFormatter
	buflogger = &BufferedLogger{
		Logger:             logger,
		bufferingFormatter: bufferingFormatter,
	}
	return buflogger
}
