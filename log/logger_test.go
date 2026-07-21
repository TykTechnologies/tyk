package log

import (
	"bytes"
	"io"
	"slices"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func Test_Logger(t *testing.T) {
	makeDummySink := func(writer io.Writer) SinkerExtended {
		return NewSink(writer, &logrus.TextFormatter{}, AcceptorAllowAll)
	}

	t.Run("Setup", func(t *testing.T) {
		t.Run("flushes setup", func(t *testing.T) {
			buf := &bytes.Buffer{}

			lgr := New()
			lgr.Info("pre-setup log")

			assert.Len(t, lgr.tmpLogsCollector.entries, 1)
			lgr.Setup(func(b *Builder) {
				b.AddSinker(makeDummySink(buf))
			})

			assert.Empty(t, lgr.tmpLogsCollector.entries)
			assert.Contains(t, buf.String(), "pre-setup log")
		})

		t.Run("panics if called twice", func(t *testing.T) {
			lgr := New()
			lgr.Setup(func(_ *Builder) {})

			assert.Panics(t, func() {
				lgr.Setup(func(_ *Builder) {})
			})
		})
	})

	t.Run("flushes to emergency logger if setup was not called", func(t *testing.T) {
		buf := bytes.Buffer{}

		lgr := New()
		lgr.emergencyLogger.SetOutput(&buf)

		lgr.Info("fatal startup error")
		assert.Len(t, lgr.tmpLogsCollector.entries, 1)

		lgr.Flush()

		assert.Empty(t, lgr.tmpLogsCollector.entries)
		assert.Contains(t, buf.String(), "fatal startup error")
	})

	t.Run("Flush", func(t *testing.T) {
		t.Run("does not add logs to output", func(t *testing.T) {
			lgr := New()
			emBuf := &bytes.Buffer{}
			lgr.emergencyLogger.SetOutput(emBuf)

			lgr.Setup(func(_ *Builder) {})

			log.Info("post-setup log")
			lgr.Flush()

			assert.Empty(t, emBuf.String())
		})
	})

	t.Run("RemoveHook", func(t *testing.T) {
		t.Run("removes hook", func(t *testing.T) {
			logger := New()
			logger.ReplaceHooks(make(logrus.LevelHooks))

			hook := &test.Hook{}
			logger.AddHook(hook)

			for _, hooks := range logger.Hooks {
				assert.True(t, len(hooks) == 1, "each logger level hes it's hook")
			}

			logger.RemoveHook(hook)

			for _, hooks := range logger.Hooks {
				assert.True(t, len(hooks) == 0, "has removed all the hooks from logger")
			}
		})
	})

	t.Run("Workflow", func(t *testing.T) {
		t.Run("keeps reference created before setup call", func(t *testing.T) {
			lgr := New()
			child := lgr.WithField("prefix", "child")
			child.Info("pre setup")

			sinkBuf := &bytes.Buffer{}

			lgr.Setup(func(b *Builder) {
				b.AddSinker(NewSink(sinkBuf, &logrus.TextFormatter{}, AcceptorAllowAll))
			})

			child.Info("post setup")
			lgr.Info("root logger call")

			lines := slices.Collect(bytes.Lines(sinkBuf.Bytes()))
			assert.True(t, len(lines) == 3)
			assert.Contains(t, string(lines[0]), "pre setup", "pre setup logs are flushed")
			assert.Contains(t, string(lines[0]), "prefix=child")
			assert.Contains(t, string(lines[1]), "post setup")
			assert.Contains(t, string(lines[1]), "prefix=child")
			assert.Contains(t, string(lines[2]), "root logger call")
			assert.NotContains(t, string(lines[2]), "prefix=child")
		})
	})
}
