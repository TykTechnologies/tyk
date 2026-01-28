package accesslog_test

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil/accesslog"
)

func TestFilter(t *testing.T) {
	in := logrus.Fields{
		"a": "b",
		"b": "c",
		"c": "d",
	}

	got := accesslog.Filter(in, []string{"a", "c"})

	want := logrus.Fields{
		"a": "b",
		"c": "d",
	}

	assert.Equal(t, want, got)
}
