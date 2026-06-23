package log_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	tyklog "github.com/TykTechnologies/tyk/log"
)

func Test_Logger_Workflow(t *testing.T) {
	t.Run("keeps reference created before setup call", func(t *testing.T) {
		log := tyklog.New()
		child := log.WithField("prefix", "child")
		child.Info("pre setup")

		sinkBuf := &bytes.Buffer{}

		log.Setup(func(b *tyklog.Builder) {
			b.AddSink(tyklog.NewSink(sinkBuf, &logrus.TextFormatter{}, tyklog.AcceptorAllowAll))
		})

		child.Info("post setup")
		log.Info("root logger call")

		lines := slices.Collect(bytes.Lines(sinkBuf.Bytes()))
		assert.True(t, len(lines) == 3)
		assert.Contains(t, string(lines[0]), "pre setup", "pre setup logs are flushed")
		assert.Contains(t, string(lines[0]), "prefix=child")
		assert.Contains(t, string(lines[1]), "post setup")
		assert.Contains(t, string(lines[1]), "prefix=child")
		assert.Contains(t, string(lines[2]), "root logger call")
		assert.NotContains(t, string(lines[2]), "prefix=child")
	})
}
