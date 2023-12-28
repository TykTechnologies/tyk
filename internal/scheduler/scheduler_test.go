package scheduler_test

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/scheduler"
)

func TestNewScheduler(t *testing.T) {
	logger, _ := test.NewNullLogger()
	execFunc := func() error { return nil }
	interval := 1 * time.Second

	s := scheduler.NewScheduler("testScheduler", interval, logger, execFunc)

	assert.NotEmpty(t, s)
}

func TestExec(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		t.Skip()
		logger, _ := test.NewNullLogger()
		var counter int64
		execFunc := func() error {
			atomic.AddInt64(&counter, 1)
			return nil
		}

		s := scheduler.NewScheduler("test", 100*time.Microsecond, logger, execFunc)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			time.Sleep(150 * time.Microsecond) // Wait for the ticker to tick at least once
			cancel()
		}()

		s.Start(ctx)
		assert.Equal(t, int64(1), counter)
	})

	t.Run("non cancelled error", func(t *testing.T) {
		t.Skip()
		logger, _ := test.NewNullLogger()
		var counter int64
		execFunc := func() error {
			atomic.AddInt64(&counter, 1)
			return io.EOF
		}

		s := scheduler.NewScheduler("test", 100*time.Microsecond, logger, execFunc)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			time.Sleep(150 * time.Microsecond) // Wait for the ticker to tick at least once
			cancel()
		}()

		s.Start(ctx)
		assert.Equal(t, int64(1), counter)
	})

	t.Run("error", func(t *testing.T) {
		logger, _ := test.NewNullLogger()
		execFunc := func() error { return context.Canceled }

		s := scheduler.NewScheduler("test", time.Nanosecond, logger, execFunc)

		s.Start(context.Background())

	})
}
