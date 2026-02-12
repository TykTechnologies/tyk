package memorycache_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/memorycache"
	"github.com/TykTechnologies/tyk/internal/model"
)

func TestBucket(t *testing.T) {
	// todo: use synctest when moved to go 1.25

	t.Run("Add", func(t *testing.T) {
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

	t.Run("State", func(t *testing.T) {
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
}
