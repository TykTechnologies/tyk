package time

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReadableDuration_MarshalJSON(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		duration := ReadableDuration(time.Minute * 5)
		expectedJSON := []byte(`"5m0s"`)
		resultJSON, err := json.Marshal(&duration)
		assert.NoError(t, err)
		assert.Equal(t, string(expectedJSON), string(resultJSON))
	})

	t.Run("0 duration", func(t *testing.T) {
		var emptyDuration = ReadableDuration(0)
		expectedJSON := []byte(`"0s"`)
		resultJSON, err := json.Marshal(emptyDuration)
		assert.NoError(t, err)
		assert.Equal(t, string(expectedJSON), string(resultJSON))
	})

	t.Run("50 milliseconds", func(t *testing.T) {
		duration := ReadableDuration(time.Millisecond * 50)
		expectedJSON := []byte(`"50ms"`)
		resultJSON, err := json.Marshal(&duration)
		assert.NoError(t, err)
		assert.Equal(t, string(expectedJSON), string(resultJSON))
	})
}

func TestReadableDuration_Seconds(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		inputJSON := []byte(`"30m50ms"`)
		var duration ReadableDuration
		err := json.Unmarshal(inputJSON, &duration)
		assert.NoError(t, err)
		assert.Equal(t, float64(1800), duration.Seconds())
	})

	t.Run("milliseconds rounded to seconds", func(t *testing.T) {
		inputJSON := []byte(`"30m2200ms"`)
		var duration ReadableDuration
		err := json.Unmarshal(inputJSON, &duration)
		assert.NoError(t, err)
		assert.Equal(t, float64(1802), duration.Seconds())
	})
}

func TestReadableDuration_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	t.Run("valid duration", func(t *testing.T) {
		inputJSON := []byte(`"2h30m"`)
		var duration ReadableDuration
		err := json.Unmarshal(inputJSON, &duration)
		assert.NoError(t, err)
		expectedDuration := ReadableDuration(time.Hour*2 + time.Minute*30)
		assert.Equal(t, expectedDuration, duration)
	})

	t.Run("milliseconds and seconds", func(t *testing.T) {
		inputJSON := []byte(`"30m12578ms"`)
		var duration ReadableDuration
		err := json.Unmarshal(inputJSON, &duration)
		assert.NoError(t, err)
		expectedDuration := ReadableDuration(time.Minute*30 + time.Millisecond*12578)
		assert.Equal(t, expectedDuration, duration)
	})

	t.Run("empty duration", func(t *testing.T) {
		emptyJSON := []byte(`""`)
		var emptyDuration ReadableDuration
		err := json.Unmarshal(emptyJSON, &emptyDuration)
		assert.NoError(t, err)
		assert.Equal(t, ReadableDuration(0), emptyDuration)

	})

	t.Run("invalid duration", func(t *testing.T) {
		invalidJSON := []byte(`"invalid"`)
		var invalidDuration ReadableDuration
		err := json.Unmarshal(invalidJSON, &invalidDuration)
		assert.NoError(t, err)
		assert.Equal(t, ReadableDuration(0), invalidDuration)
	})
}
