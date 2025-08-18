package utils_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/pkg/utils"
)

func TestUtils(t *testing.T) {
	t.Run("utils.Must", func(t *testing.T) {
		var fakeError = errors.New("fake error")

		value := func(v any, err error) (any, error) {
			return v, err
		}

		t.Run("panics is error is nil", func(t *testing.T) {
			assert.PanicsWithValue(t, fakeError, func() {
				utils.Must(value(-1, fakeError))
			})
		})

		t.Run("returns first value from tuple if error is not nil", func(t *testing.T) {
			assert.NotPanics(t, func() {
				res := utils.Must(value(-1, nil))
				assert.Equal(t, -1, res)
			})
		})
	})
}
