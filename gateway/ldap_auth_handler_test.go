package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_LDAPStorageHandler(t *testing.T) {

	newLDAPStorageHandler := func() *LDAPStorageHandler {
		return &LDAPStorageHandler{}
	}

	t.Run("SetKeyEx", func(t *testing.T) {
		t.Run("does not return error and logs warning", func(t *testing.T) {
			handler := newLDAPStorageHandler()
			err := handler.SetKeyEx("", "", 1)
			assert.NoError(t, err)
		})
	})

	t.Run("SetRawKeyEx", func(t *testing.T) {
		t.Run("does not return error and logs warning", func(t *testing.T) {
			handler := newLDAPStorageHandler()

			err := handler.SetRawKeyEx("", "", 1)
			assert.NoError(t, err)
		})
	})
}
