package scheduler_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/internal/scheduler"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
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
		logger, _ := test.NewNullLogger()
		execFuncCalled := false
		execFunc := func() error {
			execFuncCalled = true
			return nil
		}

		s := scheduler.NewScheduler("test", 100*time.Millisecond, logger, execFunc)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go s.Exec(ctx)

		time.Sleep(200 * time.Millisecond) // Wait for the ticker to tick at least once
		cancel()

		assert.True(t, execFuncCalled, "Expected execFunc to be called")
	})

	t.Run("error", func(t *testing.T) {
		logger, hook := test.NewNullLogger()
		execFunc := func() error { return errors.New("test error") }

		s := scheduler.NewScheduler("test", 100*time.Millisecond, logger, execFunc)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go s.Exec(ctx)

		time.Sleep(150 * time.Millisecond) // Wait for the ticker to tick at least once
		cancel()

		assert.Len(t, hook.Entries, 1)
		assert.Equal(t, "error while executing func test", hook.LastEntry().Message)
	})

	t.Run("cancelled context", func(t *testing.T) {
		logger, _ := test.NewNullLogger()
		execFuncCalled := false
		execFunc := func() error {
			execFuncCalled = true
			return nil
		}

		s := scheduler.NewScheduler("testCancel", 50*time.Millisecond, logger, execFunc)
		ctx, cancel := context.WithCancel(context.Background())

		go s.Exec(ctx)

		time.Sleep(25 * time.Millisecond) // Cancel before the first tick
		cancel()
		time.Sleep(100 * time.Millisecond) // Give some time to propagate the cancel

		assert.False(t, execFuncCalled, "execFunc should not have been called")
	})

	t.Run("repeated exec calls", func(t *testing.T) {
		logger, _ := test.NewNullLogger()
		callCount := 0
		execFunc := func() error {
			callCount++
			return nil
		}

		s := scheduler.NewScheduler("testRepeated", 100*time.Millisecond, logger, execFunc)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go s.Exec(ctx)

		time.Sleep(350 * time.Millisecond) // Enough time for multiple ticks
		cancel()

		assert.True(t, callCount >= 3, "execFunc should have been called at least 3 times")
	})
}
