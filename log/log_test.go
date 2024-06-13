package log

import (
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewFormatter(t *testing.T) {
	cases := []struct {
		name   string
		format string
		want   logrus.Formatter
	}{
		{
			name:   "JSON Formatter",
			format: "json",
			want: &logrus.JSONFormatter{
				TimestampFormat: time.RFC3339,
			},
		},
		{
			name:   "Text Formatter",
			format: "random string",
			want: &logrus.TextFormatter{
				TimestampFormat: "Jan 02 15:04:05",
				FullTimestamp:   true,
				DisableColors:   true,
			},
		},
		{
			name:   "Default Formatter",
			format: "",
			want: &logrus.TextFormatter{
				TimestampFormat: "Jan 02 15:04:05",
				FullTimestamp:   true,
				DisableColors:   true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NewFormatter(tc.format)

			switch want := tc.want.(type) {
			case *logrus.JSONFormatter:
				gotFormatter, ok := got.(*logrus.JSONFormatter)
				assert.True(t, ok, "Log format is not *logrus.JSONFormatter")
				assert.Equal(t, want.TimestampFormat, gotFormatter.TimestampFormat)
			case *logrus.TextFormatter:
				gotFormatter, ok := got.(*logrus.TextFormatter)
				assert.True(t, ok, "Log format is not *logrus.TextFormatter")
				assert.Equal(t, want.TimestampFormat, gotFormatter.TimestampFormat)
				assert.Equal(t, want.FullTimestamp, gotFormatter.FullTimestamp)
				assert.Equal(t, want.DisableColors, gotFormatter.DisableColors)
			}
		})
	}
}
