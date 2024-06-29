package rate

import (
	"context"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestNewAllowanceStore(t *testing.T) {
	mockRedis, _ := redismock.NewClientMock()
	store := NewAllowanceStore(mockRedis)
	assert.NotNil(t, store)
	assert.Equal(t, mockRedis, store.redis)
}

func TestAllowanceStore_Locker(t *testing.T) {
	mockRedis, _ := redismock.NewClientMock()
	store := NewAllowanceStore(mockRedis)
	locker := store.Locker("test-key")
	assert.NotNil(t, locker)
}

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
}

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

	store := NewAllowanceStore(mockRedis)
	err := store.Set(ctx, key, allowance)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())

	a1 := store.get(key)
	assert.Equal(t, allowance.Delay, a1.Delay)
	assert.Equal(t, allowance.Current, a1.Current)
}
