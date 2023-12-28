package scheduler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

func NewScheduler(name string, interval time.Duration, logger *logrus.Logger, purgeFunc func() error) *Scheduler {
	scheduler := &Scheduler{
		interval: interval,
		jobFn:    purgeFunc,
		logger:   logger.WithField("scheduler", name),
	}

	return scheduler
}

type Scheduler struct {
	interval time.Duration
	logger   *logrus.Entry
	jobFn    func() error
}

func (s *Scheduler) Start(ctx context.Context) {
	for {
		if err := s.runExecFunc(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}

			s.logger.Error(err)
			continue
		}

		s.logger.Infof("execution success")
	}
}

func (s *Scheduler) runExecFunc(ctx context.Context) error {
	tick := time.NewTicker(s.interval)
	defer tick.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tick.C:
		if err := s.jobFn(); err != nil {
			return fmt.Errorf("error while executing func: %w", err)
		}
	}

	return nil
}
