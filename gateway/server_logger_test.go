package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	stdlog "log"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/cli"
	"github.com/TykTechnologies/tyk/config"
	tyklog "github.com/TykTechnologies/tyk/log"
)

// captureStream swaps *stream for a pipe until the returned func is called.
func captureStream(t *testing.T, stream **os.File) func() string {
	t.Helper()

	orig := *stream
	r, w, err := os.Pipe()
	require.NoError(t, err)
	*stream = w

	var buf bytes.Buffer
	var copyErr error
	done := make(chan struct{})
	go func() {
		_, copyErr = io.Copy(&buf, r)
		close(done)
	}()

	restored := false
	restore := func() string {
		if !restored {
			restored = true
			*stream = orig
			require.NoError(t, w.Close())
			<-done
			require.NoError(t, copyErr)
		}
		return buf.String()
	}
	t.Cleanup(func() { restore() })

	return restore
}

func logFormatFromJSON(t *testing.T, raw string) config.LogFormat {
	t.Helper()
	var lf config.LogFormat
	require.NoError(t, json.Unmarshal([]byte(raw), &lf))
	return lf
}

const splitSinks = `[
	{"level": "debug", "high_level": "warn", "format": "json", "output": "stdout"},
	{"level": "error", "format": "text", "output": "stderr"}
]`

func buildTestLogger(t *testing.T, cfg config.Config) *tyklog.Logger {
	t.Helper()
	gw := NewGateway(cfg, t.Context())
	gw.setTestMode(false)
	return tyklog.Build(gw.setupLogger)
}

func Test_GW_setupLogger_sinks(t *testing.T) {
	t.Run("split routing", func(t *testing.T) {
		cli.InitTest(t, nil)
		stdout, stderr := captureStream(t, &os.Stdout), captureStream(t, &os.Stderr)

		l := buildTestLogger(t, config.Config{LogLevel: "debug", LogFormat: logFormatFromJSON(t, splitSinks)})
		l.Debug("debug-entry")
		l.Info("info-entry")
		l.Warn("warn-entry")
		l.Error("error-entry")

		out, errOut := stdout(), stderr()
		assert.Contains(t, out, `"message":"debug-entry"`)
		assert.Contains(t, out, `"message":"info-entry"`)
		assert.Contains(t, out, `"message":"warn-entry"`)
		assert.NotContains(t, out, "error-entry")
		assert.Contains(t, errOut, "level=error message=error-entry")
		assert.NotContains(t, errOut, "debug-entry")
		assert.NotContains(t, errOut, "info-entry")
	})

	t.Run("log_level still applies with sinks", func(t *testing.T) {
		cli.InitTest(t, nil)
		stdout, stderr := captureStream(t, &os.Stdout), captureStream(t, &os.Stderr)

		l := buildTestLogger(t, config.Config{LogLevel: "info", LogFormat: logFormatFromJSON(t, splitSinks)})
		assert.Equal(t, logrus.InfoLevel, l.GetLevel())
		l.Debug("debug-entry")
		l.Info("info-entry")

		out := stdout()
		assert.NotContains(t, out, "debug-entry")
		assert.Contains(t, out, "info-entry")
		assert.Empty(t, stderr())
	})

	t.Run("--debug generates debug entries routed by the sinks", func(t *testing.T) {
		cli.InitTest(t, nil)
		*cli.DebugMode = true
		stdout, stderr := captureStream(t, &os.Stdout), captureStream(t, &os.Stderr)

		l := buildTestLogger(t, config.Config{LogLevel: "info", LogFormat: logFormatFromJSON(t, splitSinks)})
		assert.Equal(t, logrus.DebugLevel, l.GetLevel())
		l.Debug("debug-entry")

		assert.Contains(t, stdout(), `"message":"debug-entry"`)
		assert.NotContains(t, stderr(), "debug-entry")
	})

	t.Run("TYK_GW_LOGFORMAT json array overrides the file", func(t *testing.T) {
		cli.InitTest(t, nil)
		t.Setenv(tyklog.EnvTykGwLogformat, splitSinks)
		stdout, stderr := captureStream(t, &os.Stdout), captureStream(t, &os.Stderr)

		l := buildTestLogger(t, config.Config{LogLevel: "info", LogFormat: logFormatFromJSON(t, `"legacy"`)})
		l.Info("info-entry")
		l.Error("error-entry")

		assert.Contains(t, stdout(), `"message":"info-entry"`)
		assert.Contains(t, stderr(), "level=error message=error-entry")
	})

	t.Run("blank or unknown environment values fall through to the file", func(t *testing.T) {
		cli.InitTest(t, nil)
		t.Setenv(tyklog.EnvTykLogformat, "  ")
		t.Setenv(tyklog.EnvTykGwLogformat, "yaml")
		stdout, stderr := captureStream(t, &os.Stdout), captureStream(t, &os.Stderr)

		l := buildTestLogger(t, config.Config{LogLevel: "info", LogFormat: logFormatFromJSON(t, splitSinks)})
		l.Info("info-entry")

		assert.Contains(t, stdout(), `"message":"info-entry"`)
		assert.Empty(t, stderr())
	})

	t.Run("TYK_LOGFORMAT string overrides sinks in the file", func(t *testing.T) {
		cli.InitTest(t, nil)
		t.Setenv(tyklog.EnvTykLogformat, "json")
		stdout, stderr := captureStream(t, &os.Stdout), captureStream(t, &os.Stderr)

		l := buildTestLogger(t, config.Config{LogLevel: "info", LogFormat: logFormatFromJSON(t, splitSinks)})
		l.Info("info-entry")

		assert.Empty(t, stdout())
		assert.Contains(t, stderr(), `"message":"info-entry"`)
	})

	t.Run("empty array and unknown strings fall back to text on stderr", func(t *testing.T) {
		for _, raw := range []string{`[]`, `""`, `null`, `"garbage"`} {
			t.Run(raw, func(t *testing.T) {
				cli.InitTest(t, nil)
				stdout, stderr := captureStream(t, &os.Stdout), captureStream(t, &os.Stderr)

				l := buildTestLogger(t, config.Config{LogFormat: logFormatFromJSON(t, raw)})
				l.Info("info-entry")

				assert.Empty(t, stdout())
				assert.Contains(t, stderr(), "level=info message=info-entry")
			})
		}
	})

	t.Run("standard library messages become warn entries", func(t *testing.T) {
		cli.InitTest(t, nil)
		captureStream(t, &os.Stderr)
		hook := log.GetTestHook(t)

		buildTestLogger(t, config.Config{LogFormat: logFormatFromJSON(t, splitSinks)})
		stdlog.Print("http: TLS handshake error from 10.0.0.1: EOF")

		entries := hook.FilterBy(func(e *logrus.Entry) bool { return e.Data["prefix"] == "system" })
		require.Len(t, entries, 1)
		assert.Equal(t, logrus.WarnLevel, entries[0].Level)
		assert.Equal(t, "http: TLS handshake error from 10.0.0.1: EOF", entries[0].Message)
	})

	t.Run("legacy format flag follows the string format", func(t *testing.T) {
		cli.InitTest(t, nil)
		captureStream(t, &os.Stderr)

		l := buildTestLogger(t, config.Config{LogFormat: logFormatFromJSON(t, `"legacy"`)})
		assert.True(t, l.IsLegacyFormatterEnabled())
	})

	t.Run("uncovered levels are reported on stderr when no sink shows warnings", func(t *testing.T) {
		cli.InitTest(t, nil)
		stdout, stderr := captureStream(t, &os.Stdout), captureStream(t, &os.Stderr)

		buildTestLogger(t, config.Config{
			LogLevel:  "info",
			LogFormat: logFormatFromJSON(t, `[{"level": "error", "format": "json", "output": "stdout"}]`),
		})

		assert.Empty(t, stdout())
		assert.Contains(t, stderr(), "No log sink accepts warning, info entries; they will be discarded")
	})

	t.Run("invalid sinks stop the build", func(t *testing.T) {
		cli.InitTest(t, nil)
		gw := NewGateway(config.Config{}, t.Context())

		cfg := config.Config{LogFormat: logFormatFromJSON(t, `[{"level": "loud", "format": "json", "output": "stdout"}, {"format": "json"}]`)}
		_, _, err := gw.buildSinks(&cfg)
		assert.ErrorContains(t, err, `log_format[0]: unknown level "loud"`)
		assert.ErrorContains(t, err, "log_format[1]: missing output")

		t.Setenv(tyklog.EnvTykGwLogformat, `[{"format": "json", "output": "stdout", "colour": true}]`)
		_, _, err = gw.buildSinks(&config.Config{})
		assert.ErrorContains(t, err, `TYK_GW_LOGFORMAT: log_format[0]: json: unknown field "colour"`)
	})
}
