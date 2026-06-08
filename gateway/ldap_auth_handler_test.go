package gateway

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	logger "github.com/TykTechnologies/tyk/log"
)

func Test_LDAPStorageHandler(t *testing.T) {
	const msg = "LDAP storage is READ ONLY"

	newLDAPStorageHandler := func() *LDAPStorageHandler {
		return &LDAPStorageHandler{}
	}

	t.Run("SetKeyEx", func(t *testing.T) {
		t.Run("does not return error and logs warning", func(t *testing.T) {
			handler := newLDAPStorageHandler()
			hook := logger.InjectTestHook(t)

			err := handler.SetKeyEx("", "", 1)
			assert.NoError(t, err)

			assert.Equal(t, 1, hook.CountBy(func(entry *logrus.Entry) bool {
				return entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, msg)
			}))
		})
	})

	t.Run("SetRawKeyEx", func(t *testing.T) {
		t.Run("does not return error and logs warning", func(t *testing.T) {
			handler := newLDAPStorageHandler()
			hook := logger.InjectTestHook(t)
			err := handler.SetRawKeyEx("", "", 1)
			assert.NoError(t, err)

			assert.Equal(t, 1, hook.CountBy(func(entry *logrus.Entry) bool {
				return entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, msg)
			}))
		})
	})
}
