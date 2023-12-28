package scheduler

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var Break = errors.New("internal: break scheduler loop")

type Job struct {
	Name     string
	Run      func() error
	Interval time.Duration
}

func NewJob(name string, run func() error, interval time.Duration) *Job {
	return &Job{
		Name:     name,
		Run:      run,
		Interval: interval,
	}
}

type Scheduler struct {
	logger *logrus.Logger

	mustBreak bool
	stop      chan bool
	stopOnce  sync.Once
}

func NewScheduler(logger *logrus.Logger) *Scheduler {
	return &Scheduler{
		logger: logger,
		stop:   make(chan bool),
	}
}

func (s *Scheduler) Logger() *logrus.Entry {
	return s.logger.WithField("prefix", "scheduler")
}

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

func (s *Scheduler) Close() error {
	s.stopOnce.Do(func() {
		close(s.stop)
	})
	return nil
}
