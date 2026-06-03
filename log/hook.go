package log

import (
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

type locaHookAlias = logrustest.Hook

type Hook struct {
	*locaHookAlias
}

func NewHook(base *logrustest.Hook) *Hook {
	if base == nil {
		base = new(logrustest.Hook)
	}

	return &Hook{base}
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
