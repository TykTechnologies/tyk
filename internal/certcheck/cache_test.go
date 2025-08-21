package certcheck

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/storage"
	storagemock "github.com/TykTechnologies/tyk/storage/mock"
)

func TestLocalCooldownCache_HasCheckCooldown(t *testing.T) {
	t.Run("should return false when there is no entry in cache", func(t *testing.T) {
		cache, err := NewLocalCooldownCache(2)
		require.NoError(t, err)

		exists, err := cache.HasCheckCooldown("unknown")
		assert.False(t, exists)
		assert.NoError(t, err)
	})

	t.Run("should return true when there is something in cache", func(t *testing.T) {
		cache, err := NewLocalCooldownCache(2)
		cache.lruCache.Add("does-exist", Cooldowns{})

		require.NoError(t, err)

		exists, err := cache.HasCheckCooldown("does-exist")
		assert.True(t, exists)
		assert.NoError(t, err)
	})
}

func TestLocalCooldownCache_SetCheckCooldown(t *testing.T) {
	cache, err := NewLocalCooldownCache(2)
	require.NoError(t, err)

	exists, err := cache.HasCheckCooldown("added-later")
	require.False(t, exists)
	require.NoError(t, err)

	err = cache.SetCheckCooldown("added-later", 10)
	exists, err = cache.HasCheckCooldown("added-later")
	assert.True(t, exists)
	assert.NoError(t, err)
}

func TestLocalCooldownCache_IsCheckCooldownActive(t *testing.T) {
	t.Run("should return ErrCheckCooldownDoesNotExist when there is no entry in cache", func(t *testing.T) {
		cache, err := NewLocalCooldownCache(2)
		require.NoError(t, err)
		active, err := cache.IsCheckCooldownActive("added-later")
		assert.False(t, active)
		assert.Equal(t, ErrCheckCooldownDoesNotExist, err)
	})

	t.Run("should return active = false when there is something in cache but cooldown is not active", func(t *testing.T) {
		cache, err := NewLocalCooldownCache(2)
		require.NoError(t, err)

		err = cache.SetCheckCooldown("cooldown-not-active", -120)
		require.NoError(t, err)

		active, err := cache.IsCheckCooldownActive("cooldown-not-active")
		assert.False(t, active)
		assert.NoError(t, err)
	})

	t.Run("should return active = true when there is something in cache but cooldown is not active", func(t *testing.T) {
		cache, err := NewLocalCooldownCache(2)
		require.NoError(t, err)

		err = cache.SetCheckCooldown("cooldown-not-active", 60)
		require.NoError(t, err)

		active, err := cache.IsCheckCooldownActive("cooldown-not-active")
		assert.True(t, active)
		assert.NoError(t, err)
	})
}

func TestLocalCooldownCache_HasFireEventCooldown(t *testing.T) {
	t.Run("should return false when there is no entry in cache", func(t *testing.T) {
		cache, err := NewLocalCooldownCache(2)
		require.NoError(t, err)

		exists, err := cache.HasFireEventCooldown("unknown")
		assert.False(t, exists)
		assert.NoError(t, err)
	})

	t.Run("should return true when there is something in cache", func(t *testing.T) {
		cache, err := NewLocalCooldownCache(2)
		require.NoError(t, err)

		cache.lruCache.Add("does-exist", Cooldowns{})

		exists, err := cache.HasFireEventCooldown("does-exist")
		assert.True(t, exists)
		assert.NoError(t, err)
	})
}

func TestLocalCooldownCache_SetFireEventCooldown(t *testing.T) {
	cache, err := NewLocalCooldownCache(2)
	require.NoError(t, err)

	exists, err := cache.HasFireEventCooldown("added-later")
	require.False(t, exists)
	require.NoError(t, err)

	err = cache.SetFireEventCooldown("added-later", 10)
	assert.NoError(t, err)

	exists, err = cache.HasFireEventCooldown("added-later")
	assert.True(t, exists)
	assert.NoError(t, err)
}

func TestLocalCooldownCache_IsFireEventCooldownActive(t *testing.T) {
	t.Run("should return ErrFireEventCooldownDoesNotExist when there is no entry in cache", func(t *testing.T) {
		cache, err := NewLocalCooldownCache(2)
		require.NoError(t, err)
		active, err := cache.IsFireEventCooldownActive("added-later")
		assert.False(t, active)
		assert.Equal(t, ErrFireEventCooldownDoesNotExist, err)
	})

	t.Run("should return active = false when there is something in cache but cooldown is not active", func(t *testing.T) {
		cache, err := NewLocalCooldownCache(2)
		require.NoError(t, err)

		err = cache.SetFireEventCooldown("cooldown-not-active", -120)
		require.NoError(t, err)

		active, err := cache.IsFireEventCooldownActive("cooldown-not-active")
		assert.False(t, active)
		assert.NoError(t, err)
	})

	t.Run("should return active = true when there is something in cache but cooldown is not active", func(t *testing.T) {
		cache, err := NewLocalCooldownCache(2)
		require.NoError(t, err)

		err = cache.SetFireEventCooldown("cooldown-not-active", 60)
		require.NoError(t, err)

		active, err := cache.IsFireEventCooldownActive("cooldown-not-active")
		assert.True(t, active)
		assert.NoError(t, err)
	})
}

func TestRedisCooldownCache_HasCheckCooldown(t *testing.T) {
	t.Run("should return false and error if error occurs", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().Exists(cache.checkKey("1234")).
			Return(false, errors.New("some error"))

		active, err := cache.HasCheckCooldown("1234")
		assert.False(t, active)
		assert.Error(t, err)
	})

	t.Run("should return false if check cooldown does not exist", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().Exists(cache.checkKey("1234")).
			Return(false, nil)

		active, err := cache.HasCheckCooldown("1234")
		assert.False(t, active)
		assert.NoError(t, err)
	})

	t.Run("should return true if check cooldown exists", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().Exists(cache.checkKey("1234")).
			Return(true, nil)

		active, err := cache.HasCheckCooldown("1234")
		assert.True(t, active)
		assert.NoError(t, err)
	})
}

func TestRedisCooldownCache_IsCheckCooldownActive(t *testing.T) {
	t.Run("should return false and error if error occurs", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().GetKey(cache.checkKey("1234")).
			Return("", errors.New("some error"))

		active, err := cache.IsCheckCooldownActive("1234")
		assert.False(t, active)
		assert.Error(t, err)
	})

	t.Run("should return false if no cooldown is active", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().GetKey(cache.checkKey("1234")).
			Return("", storage.ErrKeyNotFound)

		active, err := cache.IsCheckCooldownActive("1234")
		assert.False(t, active)
		assert.NoError(t, err)
	})

	t.Run("should return true if cooldown is active", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().GetKey(cache.checkKey("1234")).
			Return("1", nil)

		active, err := cache.IsCheckCooldownActive("1234")
		assert.True(t, active)
		assert.NoError(t, err)
	})
}

func TestRedisCooldownCache_SetCheckCooldown(t *testing.T) {
	t.Run("should return error if check cooldown cant be set", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().SetKey(cache.checkKey("1234"), "1", int64(60)).
			Return(errors.New("some error"))

		err = cache.SetCheckCooldown("1234", 60)
		assert.Error(t, err)
	})

	t.Run("should return no error if check cooldown can be set", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().SetKey(cache.checkKey("1234"), "1", int64(60)).
			Return(nil)

		err = cache.SetCheckCooldown("1234", 60)
		assert.NoError(t, err)
	})
}

func TestRedisCooldownCache_HasFireEventCooldown(t *testing.T) {
	t.Run("should return false and error if error occurs", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().Exists(cache.fireEventKey("1234")).
			Return(false, errors.New("some error"))

		active, err := cache.HasFireEventCooldown("1234")
		assert.False(t, active)
		assert.Error(t, err)
	})

	t.Run("should return false if check cooldown does not exist", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().Exists(cache.fireEventKey("1234")).
			Return(false, nil)

		active, err := cache.HasFireEventCooldown("1234")
		assert.False(t, active)
		assert.NoError(t, err)
	})

	t.Run("should return true if check cooldown exists", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().Exists(cache.fireEventKey("1234")).
			Return(true, nil)

		active, err := cache.HasFireEventCooldown("1234")
		assert.True(t, active)
		assert.NoError(t, err)
	})
}

func TestRedisCooldownCache_IsFireEventCooldownActive(t *testing.T) {
	t.Run("should return false and error if error occurs", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().GetKey(cache.fireEventKey("1234")).
			Return("", errors.New("some error"))

		active, err := cache.IsFireEventCooldownActive("1234")
		assert.False(t, active)
		assert.Error(t, err)
	})

	t.Run("should return false if no cooldown is active", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().GetKey(cache.fireEventKey("1234")).
			Return("", storage.ErrKeyNotFound)

		active, err := cache.IsFireEventCooldownActive("1234")
		assert.False(t, active)
		assert.NoError(t, err)
	})

	t.Run("should return true if cooldown is active", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().GetKey(cache.fireEventKey("1234")).
			Return("1", nil)

		active, err := cache.IsFireEventCooldownActive("1234")
		assert.True(t, active)
		assert.NoError(t, err)
	})
}

func TestRedisCooldownCache_SetFireEventCooldown(t *testing.T) {
	t.Run("should return error if check cooldown cant be set", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().SetKey(cache.fireEventKey("1234"), "1", int64(60)).
			Return(errors.New("some error"))

		err = cache.SetFireEventCooldown("1234", 60)
		assert.Error(t, err)
	})

	t.Run("should return no error if check cooldown can be set", func(t *testing.T) {
		ctrl, redisStorageMock := createRedisStorageMock(t)
		t.Cleanup(ctrl.Finish)

		cache, err := NewRedisCooldownCache(redisStorageMock)
		require.NoError(t, err)

		redisStorageMock.EXPECT().SetKey(cache.fireEventKey("1234"), "1", int64(60)).
			Return(nil)

		err = cache.SetFireEventCooldown("1234", 60)
		assert.NoError(t, err)
	})
}

func createRedisStorageMock(t *testing.T) (ctrl *gomock.Controller, redisStorage *storagemock.MockHandler) {
	ctrl = gomock.NewController(t)
	redisStorage = storagemock.NewMockHandler(ctrl)
	return ctrl, redisStorage
}
