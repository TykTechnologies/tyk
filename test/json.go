package test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// MarshalJSON returns a closure returning the marshalled json
// while asserting no error occurred during marshalling.
func MarshalJSON(t testing.TB) func(interface{}) []byte {
	t.Helper()

	return func(in interface{}) []byte {
		b, err := json.Marshal(in)
		require.NoError(t, err)
		return b
	}
}
