package gateway

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/request"
)

func TestGetLogEntryForRequest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	testReq := httptest.NewRequest("GET", "http://tyk.io/test", nil)
	testReq.RemoteAddr = "127.0.0.1:80"
	testData := []struct {
		EnableKeyLogging bool
		Key              string
		Data             map[string]interface{}
		Result           log.Fields
	}{
		// enable_key_logging is set, key passed, no additional data fields
		{
			EnableKeyLogging: true,
			Key:              "abc",
			Data:             nil,
			Result: log.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"key":    "abc",
			},
		},
		// enable_key_logging is set, key is not passed, no additional data fields
		{
			EnableKeyLogging: true,
			Key:              "",
			Data:             nil,
			Result: log.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
			},
		},
		// enable_key_logging is set, key passed, additional data fields are passed
		{
			EnableKeyLogging: true,
			Key:              "abc",
			Data:             map[string]interface{}{"a": 1, "b": "test"},
			Result: log.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"key":    "abc",
				"a":      1,
				"b":      "test",
			},
		},
		// enable_key_logging is set, key is not passed, additional data fields are passed
		{
			EnableKeyLogging: true,
			Key:              "",
			Data:             map[string]interface{}{"a": 1, "b": "test"},
			Result: log.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"a":      1,
				"b":      "test",
			},
		},
		// enable_key_logging is not set, key passed, no additional data field
		{
			EnableKeyLogging: false,
			Key:              "abc",
			Data:             nil,
			Result: log.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"key":    logHiddenValue,
			},
		},
		// enable_key_logging is not set, key is not passed, no additional data field
		{
			EnableKeyLogging: false,
			Key:              "",
			Data:             nil,
			Result: log.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
			},
		},
		// enable_key_logging is not set, key passed, additional data fields are passed
		{
			EnableKeyLogging: false,
			Key:              "abc",
			Data:             map[string]interface{}{"a": 1, "b": "test"},
			Result: log.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"a":      1,
				"b":      "test",
				"key":    logHiddenValue,
			},
		},
		// enable_key_logging is not set, key is not passed, additional data fields are passed
		{
			EnableKeyLogging: false,
			Key:              "",
			Data:             map[string]interface{}{"a": 1, "b": "test"},
			Result: log.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"a":      1,
				"b":      "test",
			},
		},
	}
	globalConf := ts.Gw.GetConfig()
	for _, tc := range testData {
		globalConf.EnableKeyLogging = tc.EnableKeyLogging
		ts.Gw.SetConfig(globalConf)

		logEntry := ts.Gw.getLogEntryFields(testReq.URL.Path, request.RealIP(testReq), tc.Key, tc.Data)

		assert.Equal(t, tc.Result, logEntry)

		/*
			if logEntry["path"] != tc.Result["path"] {
				t.Error("Expected 'path':", tc.Result["path"], "Got:", logEntry["path"])
			}
			if logEntry["origin"] != tc.Result["origin"] {
				t.Error("Expected 'origin':", tc.Result["origin"], "Got:", logEntry["origin"])
			}
			if logEntry["key"] != tc.Result["key"] {
				t.Error("Expected 'key':", tc.Result["key"], "Got:", logEntry["key"])
			}

			if tc.Data != nil {
				for key, val := range tc.Data {
					if logEntry[key] != val {
						t.Error("Expected data key:", key, "with value:", val, "Got:", logEntry[key])
					}
				}
			}
		*/

	}
}
