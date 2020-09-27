package gateway

import (
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/v3/config"
)

func TestGetLogEntryForRequest(t *testing.T) {
	defer ResetTestConfig()

	testReq := httptest.NewRequest("GET", "http://tyk.io/test", nil)
	testReq.RemoteAddr = "127.0.0.1:80"
	testData := []struct {
		EnableKeyLogging bool
		Key              string
		Data             map[string]interface{}
		Result           *logrus.Entry
	}{
		// enable_key_logging is set, key passed, no additional data fields
		{
			EnableKeyLogging: true,
			Key:              "abc",
			Data:             nil,
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"key":    "abc",
			}),
		},
		// enable_key_logging is set, key is not passed, no additional data fields
		{
			EnableKeyLogging: true,
			Key:              "",
			Data:             nil,
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
			}),
		},
		// enable_key_logging is set, key passed, additional data fields are passed
		{
			EnableKeyLogging: true,
			Key:              "abc",
			Data:             map[string]interface{}{"a": 1, "b": "test"},
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"key":    "abc",
				"a":      1,
				"b":      "test",
			}),
		},
		// enable_key_logging is set, key is not passed, additional data fields are passed
		{
			EnableKeyLogging: true,
			Key:              "",
			Data:             map[string]interface{}{"a": 1, "b": "test"},
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"a":      1,
				"b":      "test",
			}),
		},
		// enable_key_logging is not set, key passed, no additional data field
		{
			EnableKeyLogging: false,
			Key:              "abc",
			Data:             nil,
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"key":    obfuscateKey("abs"),
			}),
		},
		// enable_key_logging is not set, key is not passed, no additional data field
		{
			EnableKeyLogging: false,
			Key:              "",
			Data:             nil,
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
			}),
		},
		// enable_key_logging is not set, key passed, additional data fields are passed
		{
			EnableKeyLogging: false,
			Key:              "abc",
			Data:             map[string]interface{}{"a": 1, "b": "test"},
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"a":      1,
				"b":      "test",
				"key":    obfuscateKey("abc"),
			}),
		},
		// enable_key_logging is not set, key is not passed, additional data fields are passed
		{
			EnableKeyLogging: false,
			Key:              "",
			Data:             map[string]interface{}{"a": 1, "b": "test"},
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"a":      1,
				"b":      "test",
			}),
		},
	}
	globalConf := config.Global()
	for _, test := range testData {
		globalConf.EnableKeyLogging = test.EnableKeyLogging
		config.SetGlobal(globalConf)
		logEntry := getLogEntryForRequest(nil, testReq, test.Key, test.Data)
		if logEntry.Data["path"] != test.Result.Data["path"] {
			t.Error("Expected 'path':", test.Result.Data["path"], "Got:", logEntry.Data["path"])
		}
		if logEntry.Data["origin"] != test.Result.Data["origin"] {
			t.Error("Expected 'origin':", test.Result.Data["origin"], "Got:", logEntry.Data["origin"])
		}
		if logEntry.Data["key"] != test.Result.Data["key"] {
			t.Error("Expected 'key':", test.Result.Data["key"], "Got:", logEntry.Data["key"])
		}
		if test.Data != nil {
			for key, val := range test.Data {
				if logEntry.Data[key] != val {
					t.Error("Expected data key:", key, "with value:", val, "Got:", logEntry.Data[key])
				}
			}
		}
	}
}
