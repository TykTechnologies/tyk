package rate

import (
	"context"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: SW-REQ-009
// SW-REQ-009:nominal:nominal
func TestNewAllowanceStore(t *testing.T) {
	mockRedis, _ := redismock.NewClientMock()
	store := NewAllowanceStore(mockRedis)
	assert.NotNil(t, store)
	assert.Equal(t, mockRedis, store.redis)
	assert.Equal(t, "locker=0 set=0 setErrors=0 get=0 getCached=0 getErrors=0", store.String())
}

// Verifies: SW-REQ-009
// SW-REQ-009:nominal:nominal
func TestAllowanceStore_Locker(t *testing.T) {
	mockRedis, _ := redismock.NewClientMock()
	store := NewAllowanceStore(mockRedis)
	locker := store.Locker("test-key")
	assert.NotNil(t, locker)
	assert.Equal(t, "locker=1 set=0 setErrors=0 get=0 getCached=0 getErrors=0", store.String())
}

// Verifies: SW-REQ-009
// SW-REQ-009:nominal:nominal
// SW-REQ-009:boundary:boundary
func TestAllowanceStore_Get(t *testing.T) {
	mockRedis, mock := redismock.NewClientMock()
	ctx := context.Background()
	key := "test-key"

	now := time.Now()
	nextUpdateAt := now.Format(time.RFC3339Nano)
	allowanceData := map[string]string{
		"delay":        "10",
		"current":      "100",
		"nextUpdateAt": nextUpdateAt,
	}

	mock.ExpectHGetAll(Prefix(key, "allowance")).SetVal(allowanceData)

	store := NewAllowanceStore(mockRedis)
	allowance, err := store.Get(ctx, key)
	assert.NoError(t, err)
	assert.NotNil(t, allowance)
	assert.Equal(t, int64(10), allowance.Delay)
	assert.Equal(t, int64(100), allowance.Current)
	assert.Equal(t, nextUpdateAt, allowance.NextUpdateAt.Format(time.RFC3339Nano))
	assert.NoError(t, mock.ExpectationsWereMet())

	cached, err := store.Get(ctx, key)
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, allowance.Delay, cached.Delay)
	assert.Equal(t, allowance.Current, cached.Current)
	assert.Equal(t, nextUpdateAt, cached.NextUpdateAt.Format(time.RFC3339Nano))
	assert.Equal(t, "locker=0 set=0 setErrors=0 get=2 getCached=1 getErrors=0", store.String())
}

// Verifies: SW-REQ-009
// SW-REQ-009:nominal:nominal
// SW-REQ-009:boundary:boundary
func TestAllowanceStore_Set(t *testing.T) {
	mockRedis, mock := redismock.NewClientMock()
	ctx := context.Background()
	key := "test-key"

	nextUpdateAt := time.Now()

	allowance := &Allowance{
		Delay:        10,
		Current:      100,
		NextUpdateAt: nextUpdateAt,
	}

	mock.ExpectHSet(
		Prefix(key, "allowance"),
		"delay", "10",
		"current", "100",
		"nextUpdateAt", nextUpdateAt.Format(time.RFC3339Nano),
	).SetVal(1)
	mock.ExpectExpire(Prefix(key, "allowance"), 20*time.Second).SetVal(true)

	store := NewAllowanceStore(mockRedis)
	err := store.Set(ctx, key, allowance)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())

	a1 := store.get(key)
	assert.Equal(t, allowance.Delay, a1.Delay)
	assert.Equal(t, allowance.Current, a1.Current)
	assert.Equal(t, allowance.NextUpdateAt.Format(time.RFC3339Nano), a1.NextUpdateAt.Format(time.RFC3339Nano))
	assert.Equal(t, "locker=0 set=1 setErrors=0 get=0 getCached=0 getErrors=0", store.String())
}
