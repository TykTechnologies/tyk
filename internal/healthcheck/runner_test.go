package healthcheck_test

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/healthcheck"
	"github.com/TykTechnologies/tyk/test"
)

func TestRunner_Info(t *testing.T) {
	name := "TestRunner check"
	logger := test.NewBufferingLogger()

	runner := healthcheck.NewRunner(logger)
	runner.Info(healthcheck.NewFakeCheck(name, io.EOF))

	result := runner.Do(context.Background())
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
}

func TestRunner_Optional(t *testing.T) {
	name := "TestRunner check"
	logger := test.NewBufferingLogger()

	runner := healthcheck.NewRunner(logger)
	runner.Optional(healthcheck.NewFakeCheck(name, io.EOF))

	result := runner.Do(context.Background())
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
}

func TestRunner_Required(t *testing.T) {
	name := "TestRunner check"
	logger := test.NewBufferingLogger()

	runner := healthcheck.NewRunner(logger)
	runner.Require(healthcheck.NewFakeCheck(name, io.EOF))

	result := runner.Do(context.Background())
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
}
