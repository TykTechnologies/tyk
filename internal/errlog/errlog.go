package errlog

import (
	"errors"

	"github.com/sirupsen/logrus"
)

type logError struct {
	prev  error
	level logrus.Level
}

func (e logError) Unwrap() error {
	return e.prev
}

func (e logError) Error() string {
	return e.prev.Error()
}

func Wrap(err error, level logrus.Level) error {
	if err == nil {
		return nil
	}

	return logError{
		prev:  err,
		level: level,
	}
}

func Level(err error, fallback logrus.Level) logrus.Level {
	var logErr logError

	if errors.As(err, &logErr) {
		return logErr.level
	}

	return fallback
}
