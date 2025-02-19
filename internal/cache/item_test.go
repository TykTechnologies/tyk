package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestItem_Expired(t *testing.T) {
	var (
		past   = time.Now().Add(-time.Minute).UnixNano()
		future = time.Now().Add(+time.Minute).UnixNano()
	)

	type testCase struct {
		title string
		item  *Item
		want  bool
	}

	testCases := []testCase{
		{
			title: "Default item: no expiration",
			item:  &Item{},
		},
		{
			title: "Negative expiration: no expiration",
			item:  &Item{Expiration: -1},
		},
		{
			title: "Future time: record not expired",
			item:  &Item{Expiration: future},
		},
		{
			title: "Current time: record expired",
			item:  &Item{Expiration: past},
			want:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.item.Expired())
		})
	}
}
