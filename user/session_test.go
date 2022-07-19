package user

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsHashType(t *testing.T) {
	assert.False(t, IsHashType(""))
	assert.False(t, IsHashType("invalid"))
	valids := []string{"sha256", "bcrypt", "murmur32", "murmur64", "murmur128"}
	for _, ok := range valids {
		assert.True(t, IsHashType(ok))
	}
}

func TestSessionState_Lifetime(t *testing.T) {
	s := SessionState{}

	t.Run("forceGlobal=false", func(t *testing.T) {
		t.Run("respectExpiration=false", func(t *testing.T) {
			s.SessionLifetime = 1
			s.Expires = 5
			assert.Equal(t, int64(1), s.Lifetime(false, 2, false, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(2), s.Lifetime(false, 2, false, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(0), s.Lifetime(false, 0, false, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(0), s.Lifetime(false, -1, false, 3))
		})

		t.Run("respectExpiration=true", func(t *testing.T) {
			s.SessionLifetime = 1
			s.Expires = 5
			assert.Equal(t, int64(5), s.Lifetime(true, 2, false, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(5), s.Lifetime(true, 2, false, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(0), s.Lifetime(true, 0, false, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(0), s.Lifetime(true, -1, false, 3))
		})
	})

	t.Run("forceGlobal=true", func(t *testing.T) {
		t.Run("respectExpiration=false", func(t *testing.T) {
			s.SessionLifetime = 1
			assert.Equal(t, int64(3), s.Lifetime(false, 2, true, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(3), s.Lifetime(false, 2, true, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(3), s.Lifetime(false, 0, true, 3))
		})

		t.Run("respectExpiration=true", func(t *testing.T) {
			s.SessionLifetime = 1
			assert.Equal(t, int64(3), s.Lifetime(true, 2, true, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(3), s.Lifetime(true, 2, true, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(3), s.Lifetime(true, 0, true, 3))
		})
	})
}

func Test_calculateLifetime(t *testing.T) {
	t.Run("respectExpiration=false", func(t *testing.T) {
		assert.Equal(t, int64(3), calculateLifetime(false, 2, 3))
		assert.Equal(t, int64(2), calculateLifetime(false, 2, 2))
		assert.Equal(t, int64(1), calculateLifetime(false, 2, 1))
		assert.Equal(t, int64(0), calculateLifetime(false, 2, 0))
		assert.Equal(t, int64(0), calculateLifetime(false, 2, -1))
		assert.Equal(t, int64(1), calculateLifetime(false, 0, 1))
		assert.Equal(t, int64(1), calculateLifetime(false, -1, 1))
	})

	t.Run("respectExpiration=true", func(t *testing.T) {
		assert.Equal(t, int64(3), calculateLifetime(true, 2, 3))
		assert.Equal(t, int64(2), calculateLifetime(true, 2, 2))
		assert.Equal(t, int64(2), calculateLifetime(true, 2, 1))
		assert.Equal(t, int64(0), calculateLifetime(true, 2, 0))
		assert.Equal(t, int64(0), calculateLifetime(true, 2, -1))
		assert.Equal(t, int64(0), calculateLifetime(true, 0, 1))
		assert.Equal(t, int64(0), calculateLifetime(true, -1, 1))
	})
}
