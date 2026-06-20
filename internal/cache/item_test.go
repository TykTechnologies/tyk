package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Verifies: STK-REQ-021, SYS-REQ-109, SW-REQ-029
// STK-REQ-021:boundary:boundary
// SYS-REQ-109:boundary:boundary
// SW-REQ-029:boundary:nominal
// SW-REQ-029:boundary:boundary
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
