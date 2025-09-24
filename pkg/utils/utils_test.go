package utils_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/pkg/utils"
)

func TestMust(t *testing.T) {
	t.Run("panics is err is not nil", func(t *testing.T) {
		err := errors.New("err")
		assert.PanicsWithValue(t, err, func() {
			utils.Must(1, err)
		})
	})

	t.Run("returns value if error is nil", func(t *testing.T) {
		assert.NotPanics(t, func() {
			val := utils.Must(1, nil)
			assert.Equal(t, 1, val)
		})
	})
}
