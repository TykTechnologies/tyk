package user

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionState_Lifetime(t *testing.T) {
	s := SessionState{}

	t.Run("forceGlobal=false", func(t *testing.T) {
		s.SessionLifetime = 1
		assert.Equal(t, int64(1), s.Lifetime(2, false, 3))

		s.SessionLifetime = 0
		assert.Equal(t, int64(2), s.Lifetime(2, false, 3))

		s.SessionLifetime = 0
		assert.Equal(t, int64(0), s.Lifetime(0, false, 3))

		s.SessionLifetime = 0
		assert.Equal(t, int64(0), s.Lifetime(-1, false, 3))
	})

	t.Run("forceGlobal=true", func(t *testing.T) {
		s.SessionLifetime = 1
		assert.Equal(t, int64(3), s.Lifetime(2, true, 3))

		s.SessionLifetime = 0
		assert.Equal(t, int64(3), s.Lifetime(2, true, 3))

		s.SessionLifetime = 0
		assert.Equal(t, int64(3), s.Lifetime(0, true, 3))
	})
}
