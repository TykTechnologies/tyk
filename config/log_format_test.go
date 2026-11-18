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
			errContains    string
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
				name:      "Unknown string is kept, the logger falls back to text",
				inputJSON: `{"log_format": "garbage_format"}`,
				expectedStruct: TestConfig{
					LogFormat: LogFormat{
						formatType: LogFormatString,
						format:     tyklog.Format("garbage_format"),
					},
				},
			},
			{
				name:      "String case is kept as given",
				inputJSON: `{"log_format": "JSON"}`,
				expectedStruct: TestConfig{
					LogFormat: LogFormat{
						formatType: LogFormatString,
						format:     tyklog.Format("JSON"),
					},
				},
			},
			{
				name:      "Empty string is the same as not set",
				inputJSON: `{"log_format": ""}`,
				expectedStruct: TestConfig{
					LogFormat: LogFormat{formatType: LogFormatUndefined},
				},
			},
			{
				name:      "Empty array is the same as not set",
				inputJSON: `{"log_format": []}`,
				expectedStruct: TestConfig{
					LogFormat: LogFormat{formatType: LogFormatUndefined},
				},
			},
			{
				name:        "Unknown sink field is rejected",
				inputJSON:   `{"log_format": [{"format": "json", "output": "stdout"}, {"format": "json", "outptu": "stderr"}]}`,
				expectError: true,
				errContains: `log_format[1]: json: unknown field "outptu"`,
			},
			{
				name:        "Sink field of the wrong type is rejected",
				inputJSON:   `{"log_format": [{"format": "json", "output": "stdout", "level": 3}]}`,
				expectError: true,
				errContains: "log_format[0]",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var got TestConfig
				err := json.Unmarshal([]byte(tt.inputJSON), &got)

				if tt.expectError {
					assert.Error(t, err, "Expected an unmarshal error")
					if tt.errContains != "" {
						assert.ErrorContains(t, err, tt.errContains)
					}
				} else {
					assert.NoError(t, err, "Did not expect an unmarshal error")
					assert.Equal(t, tt.expectedStruct, got, "Parsed struct does not match expected state")
				}
			})
		}
	})

	t.Run("ParseLogFormatEnv", func(t *testing.T) {
		tests := []struct {
			name        string
			raw         string
			expected    LogFormat
			errContains string
		}{
			{name: "empty", raw: "", expected: LogFormat{}},
			{name: "format name is lowercased", raw: "JSON", expected: LogFormat{formatType: LogFormatString, format: tyklog.FormatJson}},
			{name: "unknown name is kept", raw: "garbage", expected: LogFormat{formatType: LogFormatString, format: tyklog.Format("garbage")}},
			{
				name: "json array of sinks",
				raw:  ` [{"format": "json", "output": "stdout", "level": "debug", "high_level": "warn"}]`,
				expected: LogFormat{formatType: LogFormatSinks, sinks: []tyklog.SinkConfig{
					{Format: "json", Output: "stdout", Level: "debug", HighLevel: "warn"},
				}},
			},
			{name: "empty array is the same as not set", raw: "[]", expected: LogFormat{}},
			{name: "unknown sink field", raw: `[{"format": "json", "output": "stdout", "colour": true}]`, errContains: `log_format[0]: json: unknown field "colour"`},
			{name: "malformed array", raw: `[{"format": "json"`, errContains: "unexpected end"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := ParseLogFormatEnv(tt.raw)
				if tt.errContains != "" {
					assert.ErrorContains(t, err, tt.errContains)
					return
				}
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, got)
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

	t.Run("Struct Composition Contract (Mixed Memory Layout)", func(t *testing.T) {
		type CombinedConfig struct {
			ByValue   LogFormat  `json:"by_value"`
			ByPointer *LogFormat `json:"by_pointer"`
		}

		lf := LogFormat{
			formatType: LogFormatString,
			format:     tyklog.Format("strict_validation"),
		}

		input := CombinedConfig{
			ByValue:   lf,
			ByPointer: &lf,
		}
		outBytes, err := json.Marshal(input)

		assert.NoError(t, err, "Unexpected error during struct marshal")
		expectedJSON := `{
        	"by_value": "strict_validation",
        	"by_pointer": "strict_validation"
    	}`

		if !assert.JSONEq(t, expectedJSON, string(outBytes),
			"Struct marshaling failed to resolve method sets consistently across value and pointer boundaries.") {

			t.Logf("received %s", string(outBytes))
			t.Logf("expected => %s", expectedJSON)
		}
	})
}
