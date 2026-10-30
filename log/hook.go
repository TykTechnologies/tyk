package log

import (
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

type innerHook = logrustest.Hook

type Hook struct {
	*innerHook
}

func NewHook(base *logrustest.Hook) *Hook {
	if base == nil {
		base = new(logrustest.Hook)
	}

	return &Hook{base}
}

// Fire stores a copy of the entry without its logger, so captured entries can be marshalled to JSON.
func (h *Hook) Fire(entry *logrus.Entry) error {
	detached := *entry
	detached.Logger = nil
	return h.innerHook.Fire(&detached)
}

func (h *Hook) SomeBy(predicate func(*logrus.Entry) bool) bool {
	return lo.SomeBy(h.AllEntries(), predicate)
}

func (h *Hook) FilterBy(predicate func(*logrus.Entry) bool) []*logrus.Entry {
	return lo.Filter(h.AllEntries(), func(item *logrus.Entry, _ int) bool {
		return predicate(item)
	})
}

func (h *Hook) CountBy(predicate func(*logrus.Entry) bool) int {
	return lo.CountBy(h.AllEntries(), predicate)
}

// HasEntryWithLevel checks if at least one log entry has level
func (h *Hook) HasEntryWithLevel(level logrus.Level) bool {
	return h.SomeBy(func(e *logrus.Entry) bool {
		return e.Level == level
	})
}
