// Package scheduler provides a simple job scheduling utility with support
// for running periodic tasks and graceful shutdown.
package scheduler

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Break is an error used to indicate the need to break the scheduler loop.
// It's an internal mechanism for stopping a job's execution within the scheduler.
var Break = errors.New("internal: break scheduler loop")

// Job represents a task that can be scheduled. Each Job has a Name, a Run function
// that performs the task, and an Interval that determines how often the task should run.
type Job struct {
	Name     string
	Run      func() error
	Interval time.Duration
}

// NewJob creates and returns a new Job with the specified name, task function, and interval.
func NewJob(name string, run func() error, interval time.Duration) *Job {
	return &Job{
		Name:     name,
		Run:      run,
		Interval: interval,
	}
}

// Scheduler is responsible for executing Jobs at specified intervals.
type Scheduler struct {
	logger *logrus.Logger

	mustBreak bool
	stop      chan bool
	stopOnce  sync.Once
}

// NewScheduler creates and returns a new Scheduler with the specified logger.
func NewScheduler(logger *logrus.Logger) *Scheduler {
	return &Scheduler{
		logger: logger,
		stop:   make(chan bool),
	}
}

// Logger creates and returns a logrus Entry with the scheduler prefix.
func (s *Scheduler) Logger() *logrus.Entry {
	return s.logger.WithField("prefix", "scheduler")
}

// Start begins the execution of the provided Job within the context of the Scheduler.
// It schedules the Job's Run function to be called at its specified interval. The job
// can be stopped via context cancellation, calling Close, or when the job returns the
// Break error.
func (s *Scheduler) Start(ctx context.Context, job *Job) {
	tick := time.NewTicker(job.Interval)

	defer func() {
		tick.Stop()
	}()

	for {
		logger := s.Logger().WithField("name", job.Name)

		err := job.Run()

		switch {
		case errors.Is(err, Break):
			s.mustBreak = true
			logger.Info("job scheduler stopping")
		case err != nil:
			logger.WithError(err).Errorf("job run error")
		default:
			logger.Info("job run successful")
		}

		if s.mustBreak {
			break
		}

		select {
		case <-s.stop:
			return
		case <-ctx.Done():
			s.Close()
			return
		case <-tick.C:
		}
	}
}

// Close gracefully stops the execution of any running Jobs in the Scheduler.
// It is safe to call multiple times and is concurrent-safe.
func (s *Scheduler) Close() error {
	s.stopOnce.Do(func() {
		close(s.stop)
	})
	return nil
}
