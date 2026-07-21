package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	tyklog "github.com/TykTechnologies/tyk/log"
)

func Test_Log_Format(t *testing.T) {
	type TestConfig struct {
		LogFormat LogFormat `json:"log_format"`
	}

	t.Run("UnmarshalJSON", func(t *testing.T) {
		tests := []struct {
			name           string
			inputJSON      string
			expectedStruct TestConfig
			expectError    bool
		}{
			{
				name:      "Valid string format provided",
				inputJSON: `{"log_format": "text"}`,
				expectedStruct: TestConfig{
					LogFormat: LogFormat{
						formatType: LogFormatString,
						format:     tyklog.Format("text"),
					},
				},
				expectError: false,
			},
			{
				name:      "Valid array of sinks provided",
				inputJSON: `{"log_format": [{}]}`,
				expectedStruct: TestConfig{
					LogFormat: LogFormat{
						formatType: LogFormatSinks,
						sinks:      []tyklog.SinkConfig{{}},
					},
				},
				expectError: false,
			},
			{
				name:      "Explicit null value provided",
				inputJSON: `{"log_format": null}`,
				expectedStruct: TestConfig{
					LogFormat: LogFormat{
						formatType: LogFormatUndefined,
					},
				},
				expectError: false,
			},
			{
				name:      "Key is completely missing",
				inputJSON: `{}`,
				expectedStruct: TestConfig{
					LogFormat: LogFormat{
						formatType: LogFormatUndefined,
					},
				},
				expectError: false,
			},
			{
				name:        "Invalid JSON structure (object instead of string/array)",
				inputJSON:   `{"log_format": {"type": "stdout"}}`,
				expectError: true,
			},
			{
				name:        "Invalid primitive type",
				inputJSON:   `{"log_format": 12345}`,
				expectError: true,
			},
			{
				name:        "Invalid string format (Valid() returns false)",
				inputJSON:   `{"log_format": "garbage_format"}`,
				expectError: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var got TestConfig
				err := json.Unmarshal([]byte(tt.inputJSON), &got)

				if tt.expectError {
					assert.Error(t, err, "Expected an unmarshal error")
				} else {
					assert.NoError(t, err, "Did not expect an unmarshal error")
					assert.Equal(t, tt.expectedStruct, got, "Parsed struct does not match expected state")
				}
			})
		}
	})

	t.Run("MarshalJSON", func(t *testing.T) {
		tests := []struct {
			name         string
			inputStruct  TestConfig
			expectedJSON string
		}{
			{
				name: "LogFormatString state serializes to string",
				inputStruct: TestConfig{
					LogFormat: LogFormat{
						formatType: LogFormatString,
						format:     tyklog.Format("text"),
					},
				},
				expectedJSON: `{"log_format": "text"}`,
			},
			{
				name: "LogFormatSinks state serializes to array",
				inputStruct: TestConfig{
					LogFormat: LogFormat{
						formatType: LogFormatSinks,
						sinks:      []tyklog.SinkConfig{{}},
					},
				},
				expectedJSON: `{"log_format": [{}]}`,
			},
			{
				name: "LogFormatUndefined state forces null output",
				inputStruct: TestConfig{
					LogFormat: LogFormat{
						formatType: LogFormatUndefined,
						format:     tyklog.Format("should_be_ignored"),
					},
				},
				expectedJSON: `{"log_format": null}`,
			},
			{
				name:         "Empty initialized struct defaults to null",
				inputStruct:  TestConfig{},
				expectedJSON: `{"log_format": null}`,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				outBytes, err := json.Marshal(&tt.inputStruct)

				assert.NoError(t, err, "Did not expect a marshal error")
				assert.JSONEq(t, tt.expectedJSON, string(outBytes), "Marshaled JSON does not match expected")
			})
		}
	})
}
