package healthcheck_test

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/healthcheck"
	"github.com/TykTechnologies/tyk/test"
)

func TestRunner(t *testing.T) {
	name := "TestRunner check"
	logger := test.NewBufferingLogger()

	runner := healthcheck.NewRunner(logger)
	runner.Require()
	runner.Optional()
	runner.Info(healthcheck.NewFakeCheck(name, io.EOF))

	result := runner.Do(context.Background())

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
