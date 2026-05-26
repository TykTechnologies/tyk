package log

import (
	"bytes"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type mockFormatter struct {
	err error
}

func (m *mockFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []byte(entry.Message), nil
}

type mockWriter struct {
	err error
}

func (m *mockWriter) Write(_ []byte) (n int, err error) {
	return 0, m.err
}

func TestNewAcceptorGte(t *testing.T) {
	acceptor := NewAcceptorGte(logrus.InfoLevel)

	assert.True(t, acceptor.Accept(&logrus.Entry{Level: logrus.InfoLevel}))
	assert.True(t, acceptor.Accept(&logrus.Entry{Level: logrus.DebugLevel}))
	assert.False(t, acceptor.Accept(&logrus.Entry{Level: logrus.ErrorLevel}))
}

func TestNewAcceptorLt(t *testing.T) {
	acceptor := NewAcceptorLt(logrus.InfoLevel)

	assert.True(t, acceptor.Accept(&logrus.Entry{Level: logrus.ErrorLevel}))
	assert.True(t, acceptor.Accept(&logrus.Entry{Level: logrus.FatalLevel}))
	assert.False(t, acceptor.Accept(&logrus.Entry{Level: logrus.InfoLevel}))
	assert.False(t, acceptor.Accept(&logrus.Entry{Level: logrus.DebugLevel}))
}

func TestNewSink(t *testing.T) {
	writer := &bytes.Buffer{}
	formatter := &mockFormatter{}
	acceptor := NewAcceptorGte(logrus.InfoLevel)

	sink := NewSink(writer, formatter, acceptor)

	assert.NotNil(t, sink)
	assert.Implements(t, (*Sink)(nil), sink)
}

func TestMultiSinkHook_Levels(t *testing.T) {
	hook := &multiSinkHook{}
	assert.Equal(t, logrus.AllLevels, hook.Levels())
}

func TestMultiSinkHook_Fire_Success(t *testing.T) {
	buf1 := &bytes.Buffer{}
	buf2 := &bytes.Buffer{}

	sink1 := NewSink(buf1, &mockFormatter{}, NewAcceptorGte(logrus.InfoLevel))
	sink2 := NewSink(buf2, &mockFormatter{}, NewAcceptorLt(logrus.InfoLevel))

	hook := &multiSinkHook{
		sinks: []Sink{sink1, sink2},
	}

	entryInfo := &logrus.Entry{Level: logrus.InfoLevel, Message: "info-msg"}
	err := hook.Fire(entryInfo)
	assert.NoError(t, err)
	assert.Equal(t, "info-msg", buf1.String())
	assert.Empty(t, buf2.String())

	buf1.Reset()
	entryErr := &logrus.Entry{Level: logrus.ErrorLevel, Message: "error-msg"}
	err = hook.Fire(entryErr)
	assert.NoError(t, err)
	assert.Empty(t, buf1.String())
	assert.Equal(t, "error-msg", buf2.String())
}

func TestMultiSinkHook_Fire_ErrorJoining(t *testing.T) {
	formatErr := errors.New("failed to format")
	writeErr := errors.New("failed to write")

	sinkFormatFail := NewSink(&bytes.Buffer{}, &mockFormatter{err: formatErr}, NewAcceptorGte(logrus.PanicLevel))
	sinkWriteFail := NewSink(&mockWriter{err: writeErr}, &mockFormatter{}, NewAcceptorGte(logrus.PanicLevel))
	sinkSuccess := NewSink(&bytes.Buffer{}, &mockFormatter{}, NewAcceptorGte(logrus.PanicLevel))

	hook := &multiSinkHook{
		sinks: []Sink{sinkFormatFail, sinkWriteFail, sinkSuccess},
	}

	err := hook.Fire(&logrus.Entry{Level: logrus.InfoLevel, Message: "test"})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), formatErr.Error())
	assert.Contains(t, err.Error(), writeErr.Error())
}

func TestAcceptorFn_Accept(t *testing.T) {
	fn := AcceptorFn(func(e *logrus.Entry) bool {
		return e.Message == "allow"
	})

	assert.True(t, fn.Accept(&logrus.Entry{Message: "allow"}))
	assert.False(t, fn.Accept(&logrus.Entry{Message: "deny"}))
}
