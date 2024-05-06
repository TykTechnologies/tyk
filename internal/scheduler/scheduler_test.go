package scheduler_test

import (
	"context"
	"io"
	"testing"
	"time"

	logrus "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/scheduler"
)

func TestScheduler_Break(t *testing.T) {
	logger, _ := logrus.NewNullLogger()

	s := scheduler.NewScheduler(logger)

	assert.NotEmpty(t, s)

	job := scheduler.NewJob("test", func() error {
		return scheduler.Break
	}, 1)

	s.Start(context.Background(), job)

	assert.NotNil(t, s)
}

func TestScheduler_Close(t *testing.T) {
	logger, _ := logrus.NewNullLogger()

	s := scheduler.NewScheduler(logger)
	defer s.Close()

	job := scheduler.NewJob("test", func() error {
		return nil
	}, 1)

	go s.Start(context.Background(), job)

	assert.NotNil(t, s)
}

func TestScheduler_Job_Errors(t *testing.T) {
	logger, _ := logrus.NewNullLogger()

	testcases := []struct {
		name string
		err  error
	}{
		{name: "no error", err: nil},
		{name: "error", err: io.EOF},
		{name: "cancelled", err: context.Canceled},
		{name: "break", err: scheduler.Break},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			job := scheduler.NewJob("test", func() error {
				return tc.err
			}, 1)

			runner := scheduler.NewScheduler(logger)
			go runner.Start(ctx, job)

			time.Sleep(time.Millisecond)
		})
	}
}
