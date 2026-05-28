package storage

import (
	"testing"

	logrus "github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func Test_TokenOrg(t *testing.T) {
	tcs := []struct {
		name           string
		givenKey       string
		expectedResult string
	}{
		{
			name:           "long non-b64 key - without orgId ",
			givenKey:       "testdata-JJNIsqyZViCvcnbX8ouvG7yctsH1irHa2aklAFYC",
			expectedResult: "",
		},
		{
			name:           "b64 key",
			givenKey:       "eyJvcmciOiI2NDkyZjY2ZTZlYmJjNTZjNmE2YmYwMjIiLCJpZCI6IjEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU5IiwiaCI6Im11cm11cjY0In0=",
			expectedResult: "6492f66e6ebbc56c6a6bf022",
		},
		{
			name:           "long non-b64 key - with orgId",
			givenKey:       "6492f66e6ebbc56c6a6bf022657c162274933214b91ea570",
			expectedResult: "6492f66e6ebbc56c6a6bf022",
		},
		{
			name:           "short non-b64 key",
			givenKey:       "6492f66e6e",
			expectedResult: "",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			result := TokenOrg(tc.givenKey)
			if result != tc.expectedResult {
				t.Errorf("Expected %s, got %s", tc.expectedResult, result)
			}
		})
	}
}

func Test_HandlerAtomicNoImplemented(t *testing.T) {
	defaultLogger := log

	logger, hook := logrustest.NewNullLogger()
	log = logger
	t.Cleanup(func() {
		log = defaultLogger
	})

	var storage HandlerAtomicNoImplemented

	t.Run("DeleteKeyAtomic", func(t *testing.T) {
		storage.DeleteKeyAtomic("")
		entry := hook.LastEntry()
		assert.Equal(t, logrus.ErrorLevel, entry.Level)
		assert.Contains(t, entry.Message, "DeleteKeyAtomic")
		assert.Contains(t, entry.Message, "not implemented")
	})

	t.Run("DeleteRawKeyAtomic", func(t *testing.T) {
		storage.DeleteRawKeyAtomic("")
		entry := hook.LastEntry()
		assert.Equal(t, logrus.ErrorLevel, entry.Level)
		assert.Contains(t, entry.Message, "DeleteRawKeyAtomic")
		assert.Contains(t, entry.Message, "not implemented")
	})

	t.Run("SetRawKeyAtomic", func(t *testing.T) {
		assert.Error(t, storage.SetRawKeyAtomic("", "", 0))
	})

	t.Run("SetKeyAtomic", func(t *testing.T) {
		assert.Error(t, storage.SetKeyAtomic("", "", 0))
	})
}
