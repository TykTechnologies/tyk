package storage

import (
	"time"

	skiplist "github.com/sean-public/fast-skiplist"
)

type slidingSortedSet struct {
	st       *skiplist.SkipList
	now      func() time.Time
	duration time.Duration
}

func newTimeSet(duration time.Duration, now func() time.Time) *slidingSortedSet {
	return &slidingSortedSet{
		st:       skiplist.New(),
		now:      now,
		duration: duration,
	}
}

// Set adds value to a sorted set using key as score. This return elements which
// is a slice of all values that haven't exceeded duration window.
func (t *slidingSortedSet) Set(key, value int64) (count int, elements []interface{}) {
	now := t.now()
	ago := float64(now.Add(-1 * t.duration).UnixNano())
	for e := t.st.Front(); e != nil; e = e.Next() {
		if e.Key() < ago {
			t.st.Remove(e.Key())
		} else {
			elements = append(elements, e.Value())
		}
	}
	t.st.Set(float64(key), value)
	return len(elements), elements
}
