package log

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewFieldMap(t *testing.T) {
	logrusMap := logrus.FieldMap{
		logrus.FieldKeyMsg:   "message",
		logrus.FieldKeyLevel: "severity",
	}

	fm := NewFieldMap(logrusMap)
	assert.Equal(t, "message", fm.fields[string(logrus.FieldKeyMsg)])
	assert.Equal(t, "severity", fm.fields[string(logrus.FieldKeyLevel)])

	fmNil := NewFieldMap(nil)
	assert.NotNil(t, fmNil.fields)
	assert.Empty(t, fmNil.fields)
}

func TestFieldMap_Resolve(t *testing.T) {
	fm := FieldMap{fields: map[string]string{
		"original_key": "mapped_key",
	}}

	assert.Equal(t, "mapped_key", fm.Resolve("original_key"))
	assert.Equal(t, "unknown_key", fm.Resolve("unknown_key"))

	fmEmpty := FieldMap{}
	assert.Equal(t, "any_key", fmEmpty.Resolve("any_key"))
}

func TestFieldMap_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		expectedMap map[string]string
	}{
		{"valid_json", `{"time":"@timestamp"}`, false, map[string]string{"time": "@timestamp"}},
		{"null_string", `null`, false, nil},
		{"invalid_json", `{"broken": json}`, true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fm FieldMap
			err := fm.UnmarshalJSON([]byte(tt.input))

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedMap, fm.fields)
			}
		})
	}
}

func TestFieldMap_MarshalJSON(t *testing.T) {
	t.Run("nil_map", func(t *testing.T) {
		fm := FieldMap{}
		data, err := fm.MarshalJSON()
		assert.NoError(t, err)
		assert.Equal(t, []byte("null"), data)
	})

	t.Run("empty_map_from_constructor", func(t *testing.T) {
		fm := NewFieldMap(nil)
		data, err := fm.MarshalJSON()
		assert.NoError(t, err)
		assert.JSONEq(t, `null`, string(data))
	})

	t.Run("populated_map", func(t *testing.T) {
		fm := FieldMap{fields: map[string]string{"key": "value"}}
		data, err := fm.MarshalJSON()
		assert.NoError(t, err)
		assert.JSONEq(t, `{"key":"value"}`, string(data))
	})
}
