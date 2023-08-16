package test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// MarshalJSON returns a closure returning the marshalled json
// while asserting no error occured during marshalling.
func MarshalJSON(t testing.TB) func(interface{}) []byte {
	return func(in interface{}) []byte {
		b, err := json.Marshal(in)
		require.NoError(t, err)
		return b
	}
}
