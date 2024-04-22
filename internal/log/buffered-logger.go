package gateway

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// implements a buffered logger mainly to be used in tests

type BufferedLog struct {
	Message string       `json:"message"`
	Time    time.Time    `json:"time"`
	Level   logrus.Level `json:"level"`
}

type BufferingFormatter struct {
	bufferMutex sync.Mutex
	buffer      []*BufferedLog
}

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

type BufferedLogger struct {
	*logrus.Logger
	bufferingFormatter *BufferingFormatter
}

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

var buflogger *BufferedLogger

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

func (bl *BufferedLogger) ClearLogs() {
	bl.bufferingFormatter.bufferMutex.Lock()
	defer bl.bufferingFormatter.bufferMutex.Unlock()
	bl.bufferingFormatter.buffer = make([]*BufferedLog, 0)
}
