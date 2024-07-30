package healthcheck_test

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/healthcheck"
	"github.com/TykTechnologies/tyk/test"
)

func TestRunner_Info(t *testing.T) {
	name := "TestRunner check"
	logger := test.NewBufferingLogger()

	runner := healthcheck.NewRunner(logger)
	runner.Info(healthcheck.NewFakeCheck(name, io.EOF))

	result := runner.Do(context.Background(), time.Second)
	result.Components[0].ObservationTS = time.Time{}

	want := healthcheck.Response{
		Status:     healthcheck.StatusPass,
		StatusCode: http.StatusOK,
		Components: []healthcheck.CheckResult{
			{
				Name:   name,
				Status: healthcheck.StatusPass,
			},
		},
	}

	assert.Equal(t, want, result)

	logOutput := logger.GetLogs(logrus.InfoLevel)
	assert.Len(t, logOutput, 1)
	assert.Regexp(t, "info: .+: EOF", logOutput[0].String())

	for i := 0; i < 100; i++ {
		got := runner.Do(context.Background(), time.Second)
		got.Components[0].ObservationTS = time.Time{}
		assert.Equal(t, want, got)
	}

	assert.Equal(t, "runner cache hits: 100, misses: 1", runner.String())
}

func TestRunner_Optional(t *testing.T) {
	name := "TestRunner check"
	logger := test.NewBufferingLogger()

	runner := healthcheck.NewRunner(logger)
	runner.Optional(healthcheck.NewFakeCheck(name, io.EOF))

	result := runner.Do(context.Background(), time.Second)
	result.Components[0].ObservationTS = time.Time{}

	want := healthcheck.Response{
		Status:     healthcheck.StatusWarn,
		StatusCode: http.StatusMultiStatus,
		Components: []healthcheck.CheckResult{
			{
				Name:   name,
				Status: healthcheck.StatusWarn,
			},
		},
	}

	assert.Equal(t, want, result)

	logOutput := logger.GetLogs(logrus.WarnLevel)
	assert.Len(t, logOutput, 1)
	assert.Regexp(t, "warning: .+: EOF", logOutput[0].String())

	for i := 0; i < 100; i++ {
		got := runner.Do(context.Background(), time.Second)
		got.Components[0].ObservationTS = time.Time{}
		assert.Equal(t, want, got)
	}

	assert.Equal(t, "runner cache hits: 100, misses: 1", runner.String())
}

func TestRunner_Required(t *testing.T) {
	name := "TestRunner check"
	logger := test.NewBufferingLogger()

	runner := healthcheck.NewRunner(logger)
	runner.Require(healthcheck.NewFakeCheck(name, io.EOF))

	result := runner.Do(context.Background(), time.Second)
	result.Components[0].ObservationTS = time.Time{}

	want := healthcheck.Response{
		Status:     healthcheck.StatusFail,
		StatusCode: http.StatusServiceUnavailable,
		Components: []healthcheck.CheckResult{
			{
				Name:   name,
				Status: healthcheck.StatusFail,
			},
		},
	}

	assert.Equal(t, want, result)

	logOutput := logger.GetLogs(logrus.ErrorLevel)
	assert.Len(t, logOutput, 1)
	assert.Regexp(t, "error: .+: EOF", logOutput[0].String())

	for i := 0; i < 100; i++ {
		got := runner.Do(context.Background(), time.Second)
		got.Components[0].ObservationTS = time.Time{}
		assert.Equal(t, want, got)
	}

	assert.Equal(t, "runner cache hits: 100, misses: 1", runner.String())
}
