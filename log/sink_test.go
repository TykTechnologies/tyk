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

func TestNewAcceptorRange(t *testing.T) {
	type testCase struct {
		name     string
		acceptor Acceptor
		accepts  []logrus.Level
		rejects  []logrus.Level
	}

	for _, tc := range []testCase{
		{
			name:     "strict",
			acceptor: NewAcceptorRange(logrus.InfoLevel, logrus.WarnLevel),
			accepts:  []logrus.Level{logrus.InfoLevel, logrus.WarnLevel},
			rejects:  []logrus.Level{logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel, logrus.DebugLevel, logrus.TraceLevel},
		},
		{
			name:     "reverted",
			acceptor: NewAcceptorRange(logrus.WarnLevel, logrus.InfoLevel),
			rejects:  []logrus.Level{logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel, logrus.DebugLevel, logrus.TraceLevel},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, level := range tc.accepts {
				assert.True(t, tc.acceptor.Accept(&logrus.Entry{Level: level}))
			}

			for _, level := range tc.rejects {
				assert.False(t, tc.acceptor.Accept(&logrus.Entry{Level: level}))
			}
		})
	}
}

func TestNewSink(t *testing.T) {
	writer := &bytes.Buffer{}
	formatter := &mockFormatter{}
	acceptor := NewAcceptorRange(logrus.InfoLevel, logrus.DebugLevel)

	sink := NewSink(writer, formatter, acceptor)

	assert.NotNil(t, sink)
	assert.Implements(t, (*Sinker)(nil), sink)
}

func TestMultiSinkHook_Levels(t *testing.T) {
	hook := &multiSinkHook{}
	assert.Equal(t, logrus.AllLevels, hook.Levels())
}

func TestMultiSinkHook_Fire_Success(t *testing.T) {
	buf1 := &bytes.Buffer{}
	buf2 := &bytes.Buffer{}

	sink1 := NewSink(buf1, &mockFormatter{}, NewAcceptorRange(logrus.DebugLevel, logrus.InfoLevel))
	sink2 := NewSink(buf2, &mockFormatter{}, NewAcceptorRange(logrus.WarnLevel, logrus.ErrorLevel))

	hook := &multiSinkHook{
		sinks: []Sinker{sink1, sink2},
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

func TestMultiSinkHook_Fire_WritesAtLeastOne(t *testing.T) {
	formatErr := errors.New("failed to format")
	writeErr := errors.New("failed to write")
	buf := &bytes.Buffer{}

	sinkFormatFail := NewSink(&bytes.Buffer{}, &mockFormatter{err: formatErr}, AcceptorAllowAll)
	sinkWriteFail := NewSink(&mockWriter{err: writeErr}, &mockFormatter{}, AcceptorAllowAll)
	sinkSuccess := NewSink(buf, &mockFormatter{}, AcceptorAllowAll)

	hook := &multiSinkHook{
		sinks: []Sinker{sinkFormatFail, sinkWriteFail, sinkSuccess},
	}

	err := hook.Fire(&logrus.Entry{Level: logrus.InfoLevel, Message: "test"})
	assert.NoError(t, err)
	assert.Equal(t, "test", buf.String(), "contains fired message")
}

func TestAcceptorFn_Accept(t *testing.T) {
	fn := AcceptorFn(func(e *logrus.Entry) bool {
		return e.Message == "allow"
	})

	assert.True(t, fn.Accept(&logrus.Entry{Message: "allow"}))
	assert.False(t, fn.Accept(&logrus.Entry{Message: "deny"}))
}
