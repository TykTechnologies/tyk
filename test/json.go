package test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// MarshalJSON returns a closure returning the marshalled json
// while asserting no error occurred during marshalling.
func MarshalJSON(tb testing.TB) func(interface{}) []byte {
	tb.Helper()

	return func(in interface{}) []byte {
		b, err := json.Marshal(in)
		require.NoError(tb, err)
		return b
	}
}
