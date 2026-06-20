package oas

import (
	"encoding/json"
	"testing"
	stdtime "time"

	"github.com/stretchr/testify/assert"

	tyktime "github.com/TykTechnologies/tyk/internal/time"
)

// Verifies: SYS-REQ-084, SW-REQ-050
// SW-REQ-050:nominal:nominal
// SW-REQ-050:boundary:nominal
// SW-REQ-050:malformed_input:nominal
// SW-REQ-050:malformed_input:negative
// SW-REQ-050:encoding_safety:nominal
// SW-REQ-050:determinism:nominal
func TestReadableDurationAliasPreservesTimingBehavior(t *testing.T) {
	t.Run("assignable to internal readable duration", func(t *testing.T) {
		internal := tyktime.ReadableDuration(5 * stdtime.Minute)
		var alias ReadableDuration = internal
		var roundTrip tyktime.ReadableDuration = alias

		assert.Equal(t, internal, roundTrip)
	})

	t.Run("marshals and converts through the alias", func(t *testing.T) {
		duration := ReadableDuration(2*stdtime.Minute + 3*stdtime.Second + 4*stdtime.Millisecond)

		first, err := json.Marshal(duration)
		assert.NoError(t, err)
		second, err := json.Marshal(duration)
		assert.NoError(t, err)

		assert.Equal(t, `"2m3s4ms"`, string(first))
		assert.Equal(t, first, second)
		assert.Equal(t, float64(123), duration.Seconds())
		assert.Equal(t, int64(123004), duration.Milliseconds())
		assert.Equal(t, int64(123004000), duration.Microseconds())
		assert.Equal(t, int64(123004000000), duration.Nanoseconds())
	})

	t.Run("unmarshals valid empty invalid and malformed inputs through the alias", func(t *testing.T) {
		var valid ReadableDuration
		assert.NoError(t, json.Unmarshal([]byte(`"1h30m"`), &valid))
		assert.Equal(t, ReadableDuration(90*stdtime.Minute), valid)

		var empty ReadableDuration
		assert.NoError(t, json.Unmarshal([]byte(`""`), &empty))
		assert.Equal(t, ReadableDuration(0), empty)

		var invalid ReadableDuration
		assert.NoError(t, json.Unmarshal([]byte(`"not-a-duration"`), &invalid))
		assert.Equal(t, ReadableDuration(0), invalid)

		var malformed ReadableDuration
		assert.EqualError(t, malformed.UnmarshalJSON([]byte(`not-json`)), "error while parsing duration")
	})
}
