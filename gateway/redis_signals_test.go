package gateway

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestPubSubInternals is an unit test for code coverage
func TestPubSubInternals(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	message := "from test, expected log output"

	testcases := []struct {
		name   string
		testFn func(*testing.T)
	}{
		{
			name: "test error log, err == nil",
			testFn: func(t *testing.T) {
				var err error
				assert.False(t, g.Gw.logPubSubError(err, message))
			},
		},
		{
			name: "test error log, err != nil",
			testFn: func(t *testing.T) {
				var err error = errors.New("test err")
				assert.True(t, g.Gw.logPubSubError(err, message))
			},
		},
		{
			name: "test add delay",
			testFn: func(t *testing.T) {
				g.Gw.addPubSubDelay(time.Microsecond)
				assert.True(t, true)
			},
		},
	}

	for idx, tc := range testcases {
		t.Run(fmt.Sprintf("Test case #%d: %s", idx, tc.name), tc.testFn)
	}
}
