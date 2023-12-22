package scheduler

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

func NewScheduler(name string, interval time.Duration, logger *logrus.Logger, purgeFunc func() error) *Scheduler {
	return &Scheduler{
		name:     name,
		interval: interval,
		execFunc: purgeFunc,
		logger:   logger,
	}
}

type Scheduler struct {
	name     string
	interval time.Duration
	execFunc func() error
	logger   *logrus.Logger
}

func (s *Scheduler) Exec(ctx context.Context) {
	tick := time.NewTicker(s.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := s.execFunc(); err != nil {
				s.logger.WithError(err).Errorf("error while executing func %s", s.name)
			} else {
				s.logger.Infof("%s execution success", s.name)
			}
		}
	}
}
