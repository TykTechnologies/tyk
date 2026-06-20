package memorycache_test

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/memorycache"
	"github.com/TykTechnologies/tyk/internal/model"
)

// Verifies: SYS-REQ-103, SW-REQ-031
// SYS-REQ-103:nominal:nominal
// SYS-REQ-103:boundary:boundary
// SYS-REQ-103:error_handling:negative
// SW-REQ-031:nominal:nominal
// SW-REQ-031:boundary:nominal
// SW-REQ-031:boundary:boundary
// SW-REQ-031:error_handling:nominal
// SW-REQ-031:error_handling:negative
func TestBucket(t *testing.T) {
	t.Run("Add", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const capacity = 5

			bucket := memorycache.NewBucket(capacity, time.Millisecond)
			for range capacity {
				_, err := bucket.Add(1)
				assert.NoError(t, err)
			}

			_, err := bucket.Add(1)
			assert.ErrorIs(t, err, model.ErrBucketFull, "blocks if limit exceeded")

			// resets time after
			time.Sleep(time.Millisecond + time.Microsecond)

			_, err = bucket.Add(1)
			assert.NoError(t, err, "unlocks after timeout")
		})
	})

	t.Run("State", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const capacity = 5
			bucket := memorycache.NewBucket(capacity, time.Millisecond)

			for range capacity {
				stateOnAdd, err := bucket.Add(1)
				assert.NoError(t, err)
				stateOnGet := bucket.State()
				assert.Equal(t, stateOnGet, stateOnAdd)
			}

			_, err := bucket.Add(1)
			assert.ErrorIs(t, err, model.ErrBucketFull, "blocks if limit exceeded")
			assert.True(t, bucket.State().Remaining == 0, "remaining state zero")

			time.Sleep(time.Millisecond + time.Microsecond)

			assert.True(t, bucket.State().Remaining == capacity, "resets state")
		})
	})
}
