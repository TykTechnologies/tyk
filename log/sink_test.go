package log

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
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

func TestNewSinkFromConfig(t *testing.T) {
	t.Run("values are case-insensitive", func(t *testing.T) {
		sink, err := NewSinkFromConfig(SinkConfig{Level: "Debug", HighLevel: "WARN", Format: "JSON", Output: "STDOUT"})
		assert.NoError(t, err)
		assert.Equal(t, os.Stdout, sink.logger.Out)
		assert.IsType(t, &JSONFormatter{}, sink.logger.Formatter)
		assert.True(t, sink.Accept(&logrus.Entry{Level: logrus.DebugLevel}))
		assert.True(t, sink.Accept(&logrus.Entry{Level: logrus.WarnLevel}))
		assert.False(t, sink.Accept(&logrus.Entry{Level: logrus.ErrorLevel}))
	})

	t.Run("level defaults to info and high_level to panic", func(t *testing.T) {
		sink, err := NewSinkFromConfig(SinkConfig{Format: "text", Output: "stderr"})
		assert.NoError(t, err)
		assert.False(t, sink.Accept(&logrus.Entry{Level: logrus.DebugLevel}))
		assert.True(t, sink.Accept(&logrus.Entry{Level: logrus.InfoLevel}))
		assert.True(t, sink.Accept(&logrus.Entry{Level: logrus.PanicLevel}))
	})

	t.Run("fatal and panic are valid sink levels", func(t *testing.T) {
		sink, err := NewSinkFromConfig(SinkConfig{Level: "fatal", HighLevel: "panic", Format: "text", Output: "stderr"})
		assert.NoError(t, err)
		assert.False(t, sink.Accept(&logrus.Entry{Level: logrus.ErrorLevel}))
		assert.True(t, sink.Accept(&logrus.Entry{Level: logrus.FatalLevel}))
	})

	for _, tc := range []struct {
		name string
		cfg  SinkConfig
		err  string
	}{
		{"missing format", SinkConfig{Output: "stdout"}, "missing format"},
		{"missing output", SinkConfig{Format: "json"}, "missing output"},
		{"unknown format", SinkConfig{Format: "yaml", Output: "stdout"}, `unknown formatter "yaml"`},
		{"unknown output", SinkConfig{Format: "json", Output: "file"}, `unknown output "file"`},
		{"unknown level", SinkConfig{Format: "json", Output: "stdout", Level: "verbose"}, `unknown level "verbose"`},
		{"unknown high_level", SinkConfig{Format: "json", Output: "stdout", HighLevel: "trace"}, `unknown high_level "trace"`},
		{"unknown format option", SinkConfig{Format: "json", Output: "stdout", FormatOptions: json.RawMessage(`{"pretty": true}`)}, `unknown field "pretty"`},
		{"output options for stdout", SinkConfig{Format: "json", Output: "stdout", OutputOptions: json.RawMessage(`{"path": "x"}`)}, "takes no output_options"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink, err := NewSinkFromConfig(tc.cfg)
			assert.Nil(t, sink)
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func TestNewSinksFromConfig(t *testing.T) {
	sinks, err := NewSinksFromConfig([]SinkConfig{
		{Format: "json", Output: "stdout"},
		{Format: "json", Output: "nowhere"},
		{Format: "", Output: "stderr"},
	})
	assert.Len(t, sinks, 1)
	assert.ErrorContains(t, err, `log_format[1]: unknown output "nowhere"`)
	assert.ErrorContains(t, err, "log_format[2]: missing format")
}

func TestParseSinkConfigs(t *testing.T) {
	sinks, err := ParseSinkConfigs([]byte(`[{"format": "json", "output": "stdout", "format_options": {"data_key": "d"}}]`))
	assert.NoError(t, err)
	assert.Equal(t, []SinkConfig{{Format: "json", Output: "stdout", FormatOptions: json.RawMessage(`{"data_key": "d"}`)}}, sinks)

	_, err = ParseSinkConfigs([]byte(`[{"format": "json", "output": "stdout"}, {"format": "json", "destination": "stderr"}]`))
	assert.ErrorContains(t, err, `log_format[1]: json: unknown field "destination"`)

	_, err = ParseSinkConfigs([]byte(`[{"format": 1}]`))
	assert.ErrorContains(t, err, "log_format[0]")
}

func TestUncoveredLevels(t *testing.T) {
	errorsOnly := NewAcceptorRange(logrus.ErrorLevel, logrus.PanicLevel)
	debugToWarn := NewAcceptorRange(logrus.DebugLevel, logrus.WarnLevel)

	assert.Equal(t, []logrus.Level{logrus.WarnLevel, logrus.InfoLevel}, UncoveredLevels(logrus.InfoLevel, errorsOnly))
	assert.Empty(t, UncoveredLevels(logrus.DebugLevel, errorsOnly, debugToWarn))
	assert.Equal(t, []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel}, UncoveredLevels(logrus.InfoLevel, debugToWarn))
	assert.Len(t, UncoveredLevels(logrus.DebugLevel), 6, "no sinks at all")
}
