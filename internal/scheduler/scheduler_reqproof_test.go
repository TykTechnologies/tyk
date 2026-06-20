package scheduler_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/scheduler"
)

// Verifies: STK-REQ-045, SYS-REQ-133, SW-REQ-120
// MCDC SYS-REQ-133: scheduler_local_operation_terminal=T => TRUE
// STK-REQ-045:nominal:nominal
// STK-REQ-045:boundary:nominal
// STK-REQ-045:error_handling:negative
// STK-REQ-045:cancellation_observed:nominal
// STK-REQ-045:concurrent:race
// STK-REQ-045:determinism:nominal
// SYS-REQ-133:nominal:nominal
// SYS-REQ-133:boundary:nominal
// SYS-REQ-133:error_handling:nominal
// SYS-REQ-133:error_handling:negative
// SYS-REQ-133:cancellation_observed:nominal
// SYS-REQ-133:concurrent:nominal
// SYS-REQ-133:concurrent:race
// SYS-REQ-133:determinism:nominal
// SW-REQ-120:nominal:nominal
// SW-REQ-120:boundary:nominal
// SW-REQ-120:error_handling:nominal
// SW-REQ-120:error_handling:negative
// SW-REQ-120:cancellation_observed:nominal
// SW-REQ-120:concurrent:nominal
// SW-REQ-120:concurrent:race
// SW-REQ-120:determinism:nominal
//
//mcdc:ignore SYS-REQ-133: scheduler_local_operation_terminal=F => FALSE -- the onboarded scheduler operations are synchronous local construction, logger decoration, start-loop termination, context shutdown, or close operations that return observable values or return from Start; a non-terminal local operation result is not a reachable API state in this proof slice [category: defensive] [reviewed: human:buger]
func TestSchedulerPreservesLocalOperationBehavior(t *testing.T) {
	t.Run("constructs jobs and scheduler logger deterministically", func(t *testing.T) {
		run := func() error { return nil }

		cases := []struct {
			name     string
			jobName  string
			interval time.Duration
		}{
			{name: "one second interval", jobName: "periodic", interval: time.Second},
			{name: "minimal interval", jobName: "immediate", interval: time.Nanosecond},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				job := scheduler.NewJob(tc.jobName, run, tc.interval)
				assert.Equal(t, tc.jobName, job.Name)
				assert.Equal(t, tc.interval, job.Interval)
				assert.NotNil(t, job.Run)

				logger, _ := test.NewNullLogger()
				runner := scheduler.NewScheduler(logger)
				assert.Equal(t, "scheduler", runner.Logger().Data["prefix"])
				require.NoError(t, runner.Close())
				require.NoError(t, runner.Close())
			})
		}
	})

	t.Run("start loop reaches terminal outcomes for break and context shutdown", func(t *testing.T) {
		cases := []struct {
			name         string
			runErr       error
			cancelOnRun  bool
			wantRuns     int
			wantErrorLog bool
		}{
			{name: "break stops immediately", runErr: scheduler.Break, wantRuns: 1},
			{name: "nil run remains stoppable by context", cancelOnRun: true, wantRuns: 1},
			{name: "non break error is logged and remains stoppable by context", runErr: io.EOF, cancelOnRun: true, wantRuns: 1, wantErrorLog: true},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				logger, hook := test.NewNullLogger()
				runner := scheduler.NewScheduler(logger)
				defer runner.Close()

				var runCount int
				job := scheduler.NewJob("reqproof", func() error {
					runCount++
					if tc.cancelOnRun {
						cancel()
					}
					return tc.runErr
				}, time.Hour)

				done := make(chan struct{})
				go func() {
					runner.Start(ctx, job)
					close(done)
				}()

				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("scheduler did not reach a terminal outcome")
				}

				assert.Equal(t, tc.wantRuns, runCount)
				if tc.wantErrorLog {
					require.NotEmpty(t, hook.AllEntries())
					assert.True(t, errors.Is(hook.LastEntry().Data["error"].(error), io.EOF))
				}
			})
		}
	})

	t.Run("close is safe under repeated concurrent calls", func(t *testing.T) {
		logger, _ := test.NewNullLogger()
		runner := scheduler.NewScheduler(logger)

		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				assert.NoError(t, runner.Close())
			}()
		}
		wg.Wait()
		assert.NoError(t, runner.Close())
	})
}
