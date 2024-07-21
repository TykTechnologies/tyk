package rpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/vmihailenco/msgpack.v2"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

func TestDecodeAnalyticsRecord(t *testing.T) {

	validRecord := analytics.AnalyticsRecord{
		Method: "POST",
	}
	validEncoded, err := msgpack.Marshal(&validRecord)
	assert.Nil(t, err)

	// Test cases
	testCases := []struct {
		name        string
		input       interface{}
		expectError bool
	}{
		{
			name: "Valid input",
			// convert to string so we emulate like reading from redis
			input:       string(validEncoded),
			expectError: false,
		},
		{
			name:        "Invalid input",
			input:       "invalidEncodedData",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeAnalyticsRecord(tc.input)

			if tc.expectError && err == nil {
				t.Error("Expected an error, but got none")
			}

			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestProcessAnalyticsValues(t *testing.T) {
	validRecord := analytics.AnalyticsRecord{
		Method: "POST",
	}
	validEncoded, err := msgpack.Marshal(&validRecord)
	assert.Nil(t, err)
	validEncodedAsString := string(validEncoded)

	// Test cases
	testCases := []struct {
		name            string
		analyticsValues []interface{}
		expectedLen     int
		expectError     bool
		failedRecords   int
	}{
		{
			name:            "Valid analytics values",
			analyticsValues: []interface{}{validEncodedAsString, validEncodedAsString},
			expectedLen:     2,
			failedRecords:   0,
			expectError:     false,
		},
		{
			name:            "Invalid analytics value",
			analyticsValues: []interface{}{validEncodedAsString, "invalidData"},
			expectedLen:     2,
			failedRecords:   1,
			expectError:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keys, failedRecords := processAnalyticsValues(tc.analyticsValues)
			assert.Equal(t, tc.failedRecords, failedRecords)
			assert.Equal(t, tc.expectedLen, len(keys))
		})
	}
}
